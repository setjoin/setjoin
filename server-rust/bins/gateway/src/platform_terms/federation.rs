//! Group `federation`: Go's `FederationHandler` (`/admin/federation/peers*`), all behind
//! `federation.manage`. Validation that lives in the handler stays here: the real X.509
//! parse of the pasted anchor and the refusal of this server's own domain.
use super::{Action, Env};
use crate::{Body, Response};
use hyper::Request;
use serde::de::{MapAccess, Visitor};
use setjoin_pg::{CommandOutcome, Rejection};
use setjoin_platform::federation;

#[derive(Default)]
struct Peer {
    domain: String,
    anchor: String,
    scope: String,
    enabled: bool,
}
impl<'de> serde::Deserialize<'de> for Peer {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Peer;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Peer, E> {
                Ok(Peer::default())
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Peer, M::Error> {
                let mut peer = Peer::default();
                while let Some(key) = map.next_key::<String>()? {
                    match crate::guests_input::fold(&key).as_str() {
                        "domain" => {
                            if let Some(v) = map.next_value::<Option<String>>()? {
                                peer.domain = v;
                            }
                        }
                        "anchorpem" => {
                            if let Some(v) = map.next_value::<Option<String>>()? {
                                peer.anchor = v;
                            }
                        }
                        "scope" => {
                            if let Some(v) = map.next_value::<Option<String>>()? {
                                peer.scope = v;
                            }
                        }
                        "enabled" => {
                            if let Some(v) = map.next_value::<Option<bool>>()? {
                                peer.enabled = v;
                            }
                        }
                        _ => {
                            let _: serde::de::IgnoredAny = map.next_value()?;
                        }
                    }
                }
                Ok(peer)
            }
        }
        decoder.deserialize_any(V)
    }
}

/// Go's `pem.Decode` followed by `x509.ParseCertificate` on the first decodable block.
fn certificate_ok(text: &str) -> bool {
    use base64::Engine as _;
    use x509_parser::prelude::FromDer as _;
    let mut rest = text;
    loop {
        let start = if rest.starts_with("-----BEGIN ") {
            0
        } else if let Some(i) = rest.find("\n-----BEGIN ") {
            i + 1
        } else {
            return false;
        };
        let block = &rest[start + 11..];
        let Some(line_end) = block.find("-----") else {
            return false;
        };
        let kind = &block[..line_end];
        let after = &block[line_end + 5..];
        let body_start = after
            .strip_prefix("\r\n")
            .or_else(|| after.strip_prefix('\n'))
            .or(Some(after).filter(|a| a.is_empty()));
        let end_marker = format!("-----END {kind}-----");
        if let (Some(body), true) = (body_start, !kind.contains('\n')) {
            if let Some(end) = body.find(&end_marker) {
                let mut lines: Vec<&str> = body[..end].lines().collect();
                // A header section ends at the first blank line.
                if lines.first().is_some_and(|l| l.contains(':')) {
                    match lines.iter().position(|l| l.trim().is_empty()) {
                        Some(i) => lines.drain(..=i).for_each(drop),
                        None => lines.clear(),
                    }
                }
                let joined: String = lines
                    .iter()
                    .flat_map(|l| l.chars())
                    .filter(|c| !matches!(c, ' ' | '\t' | '\r'))
                    .collect();
                if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(joined) {
                    return matches!(
                        x509_parser::certificate::X509Certificate::from_der(&der),
                        Ok((rest, _)) if rest.is_empty()
                    );
                }
            }
        }
        rest = &rest[start + 11..];
    }
}

/// Go's `reducererr.WriteClassified` for the codes the two writers raise.
fn classified(e: &setjoin_pg::StatementFailure, env: &Env<'_>) -> Response<Body> {
    let (status, detail, remediation) = match e.sqlstate.as_deref() {
        Some("BZ207") => (
            400,
            "invalidArguments",
            "Correct the request fields and retry.",
        ),
        Some("BZ208") => (
            409,
            "conflict",
            "Refresh current state, resolve the conflict, and retry.",
        ),
        _ => return env.database(),
    };
    let code = e.sqlstate.as_deref().unwrap_or_default();
    let mut response = env.problem(status, detail);
    let text = crate::problem::Problem::new(status, detail)
        .kind(&format!(
            "https://setjoin.com/problems/reducer/{}",
            code.to_ascii_lowercase()
        ))
        .instance(env.go_path)
        .remediation(remediation)
        .code(code)
        .retryable(false)
        .body();
    crate::problem::set_body(&mut response, text);
    response
}

pub(super) async fn run(what: Action, mut r: Request<Body>, e: &Env<'_>) -> Response<Body> {
    match what {
        Action::PeerList => match setjoin_platform::federation::list(e.worker).await {
            Ok(body) => {
                let _ = federation::audit_list(
                    e.exec,
                    e.actor,
                    &e.c.identity.client_ip.to_string(),
                    e.operation,
                )
                .await;
                e.reply(body, 200)
            }
            Err(_) => e.database(),
        },
        Action::PeerUpsert => {
            let Ok(peer) = super::json_body::<Peer>(&mut r, 1 << 20).await else {
                return e.problem(400, "invalid JSON");
            };
            let domain = crate::guests_input::lower(peer.domain.trim());
            let domain = domain.trim().to_owned();
            if domain.is_empty() {
                return e.problem(400, "domain is required");
            }
            if peer.scope != "dm" && peer.scope != "room" {
                return e.problem(400, "scope must be dm or room");
            }
            if !e.local_domain.is_empty() && domain == e.local_domain {
                return e.problem(400, "cannot allow-list this server's own domain");
            }
            let mut anchor = peer.anchor.clone();
            if anchor.trim().is_empty() {
                match federation::anchor(e.worker, &domain).await {
                    Ok(Some(stored)) => anchor = stored,
                    Ok(None) => return e.problem(400, "anchor is required for a new peer"),
                    Err(_) => return e.database(),
                }
            }
            if !certificate_ok(&anchor) {
                return e.problem(400, "anchor must be a valid PEM-encoded X.509 certificate");
            }
            match federation::set(
                e.exec,
                e.actor,
                &domain,
                &anchor,
                &peer.scope,
                peer.enabled,
                e.operation,
            )
            .await
            {
                CommandOutcome::Committed(()) => e.no_content(),
                CommandOutcome::RolledBack(Rejection::Statement(f) | Rejection::Body(f)) => {
                    classified(&f, e)
                }
                CommandOutcome::RolledBack(_) => e.database(),
                CommandOutcome::Unknown { operation } => e.unknown(operation),
            }
        }
        _ => {
            let raw = r.uri().path().split('/').nth(5).unwrap_or("");
            let domain = crate::guests_input::go_utf8(&crate::inventory::unescape(raw));
            let domain = crate::guests_input::lower(domain.trim());
            let domain = domain.trim().to_owned();
            if domain.is_empty() {
                return e.problem(400, "invalid domain");
            }
            match federation::delete(e.exec, e.actor, &domain, e.operation).await {
                CommandOutcome::Committed(true) => e.no_content(),
                CommandOutcome::Committed(false) => e.problem(404, "peer not found"),
                CommandOutcome::RolledBack(Rejection::Statement(f) | Rejection::Body(f)) => {
                    classified(&f, e)
                }
                CommandOutcome::RolledBack(_) => e.database(),
                CommandOutcome::Unknown { operation } => e.unknown(operation),
            }
        }
    }
}
