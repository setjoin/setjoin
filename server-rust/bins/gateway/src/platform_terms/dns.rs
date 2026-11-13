//! Group `dns`: Go's `DNSHandler` (`/admin/dns/records`, `/admin/dns/verify`), both behind
//! `requireMailPerm`. A domain-scoped principal may only ask about its own domain.
use super::{Action, Env};
use crate::{Body, Response};
use hyper::Request;
use setjoin_platform::dns;

pub(super) async fn run(what: Action, r: Request<Body>, e: &Env<'_>) -> Response<Body> {
    let raw = crate::admin_identity_input::query(r.uri(), "domain").unwrap_or_default();
    let domain = raw.trim().to_owned();
    if domain.is_empty() {
        return e.bare(400, "domain required");
    }
    let scope = e.authority.domain_scope();
    if scope > 0 {
        let Ok(Some(name)) = dns::scope_name(e.exec, scope).await else {
            return e.bare(403, "domain not found");
        };
        if crate::guests_input::lower(&domain) != crate::guests_input::lower(&name) {
            return e.bare(403, "access denied: domain not in scope");
        }
    }
    let body = if what == Action::DnsRecords {
        dns::records(e.exec, &domain).await
    } else {
        dns::verify(e.exec, e.resolver, &domain).await
    };
    e.reply(body, 200)
}
