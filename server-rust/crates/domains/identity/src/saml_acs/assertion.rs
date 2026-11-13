//! Reads the verified (canonical) element and applies the Web Browser SSO checks:
//! Issuer, Audience, Destination, Recipient, time window with a bounded skew,
//! bearer SubjectConfirmation and InResponseTo. Nothing here sees unverified XML.
use super::xml::{self, child_els, is_el, SAML, SAMLP};
use super::Fail;
use roxmltree::Node;
use std::collections::BTreeMap;

/// Clock skew allowed on every time bound (the ticket's ceiling is three minutes).
pub const SKEW: i64 = 120;
/// Longest remaining validity of a bearer confirmation (24 hours).
const MAX_LIFETIME: i64 = 24 * 3600;
const SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
const BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
const TRANSIENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
const ENTITY_FORMAT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";

/// What the SP expects of this particular response.
pub struct Expect<'a> {
    pub idp_entity_id: &'a str,
    /// Audience values this SP answers to (its Issuer string, its entity ID).
    pub audiences: &'a [String],
    /// The exact ACS URL; Destination and Recipient must equal it.
    pub acs_url: &'a str,
    /// The request this response must answer; None only for IdP-initiated SSO.
    pub in_response_to: Option<&'a str>,
    pub now: i64,
}

pub struct Claims {
    pub assertion_id: String,
    pub name_id: String,
    pub in_response_to: Option<String>,
    pub not_on_or_after: i64,
    pub attributes: BTreeMap<String, Vec<String>>,
}

fn bad(class: &'static str, detail: &'static str) -> Fail {
    Fail::new(class, detail)
}

pub fn time(value: &str) -> Option<i64> {
    // xs:dateTime in UTC or with an offset; a value without a zone is refused.
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|t| t.timestamp())
}

fn one<'a, 'i>(node: Node<'a, 'i>, local: &'a str) -> Result<Node<'a, 'i>, Fail> {
    let mut it = child_els(node, SAML, local);
    match (it.next(), it.next()) {
        (Some(n), None) => Ok(n),
        _ => Err(bad("structure", "malformed assertion structure")),
    }
}

/// Apply every check to the canonical signed element (a Response or an Assertion).
pub fn claims(canonical: &str, expect: &Expect<'_>) -> Result<Claims, Fail> {
    let doc = xml::parse(canonical)?;
    let root = doc.root_element();
    let assertion = if is_el(root, SAMLP, "Response") {
        response_checks(root, expect)?
    } else if is_el(root, SAML, "Assertion") {
        root
    } else {
        return Err(bad(
            "structure",
            "signed element is neither Response nor Assertion",
        ));
    };
    assertion_claims(assertion, expect)
}

fn response_checks<'a, 'i>(root: Node<'a, 'i>, expect: &Expect<'_>) -> Result<Node<'a, 'i>, Fail> {
    // A signed Response vouches for its own attributes, so they are all required.
    if root.attribute("Destination") != Some(expect.acs_url)
        && !crate::mutants::on("saml-destination")
    {
        return Err(bad("destination", "Destination is not this ACS"));
    }
    let status = root
        .children()
        .find(|c| is_el(*c, SAMLP, "Status"))
        .and_then(|s| s.children().find(|c| is_el(*c, SAMLP, "StatusCode")))
        .and_then(|c| c.attribute("Value"));
    if status != Some(SUCCESS) && !crate::mutants::on("saml-status") {
        return Err(bad("status", "the IdP did not report success"));
    }
    if let Some(issuer) = child_els(root, SAML, "Issuer").next() {
        if xml::text_of(issuer) != expect.idp_entity_id && !crate::mutants::on("saml-issuer") {
            return Err(bad("issuer", "Response Issuer is not the registered IdP"));
        }
    }
    check_response_irt(root, expect)?;
    let mut it = child_els(root, SAML, "Assertion");
    match (it.next(), it.next()) {
        (Some(a), None) => Ok(a),
        _ => Err(bad("structure", "exactly one Assertion is required")),
    }
}

/// `InResponseTo` on the Response, when present, must be the expected request.
pub fn check_response_irt(root: Node<'_, '_>, expect: &Expect<'_>) -> Result<(), Fail> {
    match (root.attribute("InResponseTo"), expect.in_response_to) {
        (Some(got), Some(want)) if got == want => Ok(()),
        (None, _) => Ok(()),
        _ if crate::mutants::on("saml-in-response-to") => Ok(()),
        _ => Err(bad(
            "inresponseto",
            "Response is not an answer to this login",
        )),
    }
}

fn assertion_claims(a: Node<'_, '_>, expect: &Expect<'_>) -> Result<Claims, Fail> {
    if a.attribute("Version") != Some("2.0") {
        return Err(bad("structure", "unsupported SAML version"));
    }
    let id = a
        .attribute("ID")
        .filter(|s| !s.is_empty() && s.len() <= 512)
        .ok_or_else(|| bad("structure", "Assertion has no ID"))?;
    let issuer = one(a, "Issuer")?;
    if xml::text_of(issuer) != expect.idp_entity_id && !crate::mutants::on("saml-issuer") {
        return Err(bad("issuer", "Assertion Issuer is not the registered IdP"));
    }
    if issuer
        .attribute("Format")
        .is_some_and(|f| f != ENTITY_FORMAT)
    {
        return Err(bad("issuer", "unexpected Issuer format"));
    }
    let skew = if crate::mutants::on("saml-skew") {
        3600
    } else {
        SKEW
    };
    // Subject: one NameID, exactly one bearer confirmation.
    let subject = one(a, "Subject")?;
    let name_id_node = one(subject, "NameID")?;
    let name_id = xml::text_of(name_id_node);
    if name_id.is_empty() || name_id.len() > 1024 || name_id.chars().any(char::is_control) {
        return Err(bad(
            "nameid",
            "NameID is empty, oversized or has control characters",
        ));
    }
    if name_id_node.attribute("Format") == Some(TRANSIENT)
        && !crate::mutants::on("saml-transient-nameid")
    {
        return Err(bad("nameid", "a transient NameID is not a stable subject"));
    }
    let confirmation = one(subject, "SubjectConfirmation")?;
    if confirmation.attribute("Method") != Some(BEARER) && !crate::mutants::on("saml-bearer") {
        return Err(bad("subject", "only bearer confirmation is accepted"));
    }
    let data = one(confirmation, "SubjectConfirmationData")?;
    if data.attribute("Recipient") != Some(expect.acs_url) && !crate::mutants::on("saml-recipient")
    {
        return Err(bad("recipient", "Recipient is not this ACS"));
    }
    if data.attribute("NotBefore").is_some() {
        return Err(bad(
            "subject",
            "bearer confirmation must not carry NotBefore",
        ));
    }
    let scd_end = data
        .attribute("NotOnOrAfter")
        .and_then(time)
        .ok_or_else(|| {
            bad(
                "conditions",
                "bearer confirmation has no valid NotOnOrAfter",
            )
        })?;
    if expect.now >= scd_end.saturating_add(skew) && !crate::mutants::on("saml-expiry") {
        return Err(bad("conditions", "the assertion has expired"));
    }
    // The replay cache keeps a row until the assertion can no longer be presented, so
    // an assertion that could be presented for years is refused instead.
    if scd_end > expect.now.saturating_add(MAX_LIFETIME + skew)
        && !crate::mutants::on("saml-lifetime")
    {
        return Err(bad(
            "conditions",
            "the assertion's validity is unreasonably long",
        ));
    }
    let irt = data.attribute("InResponseTo");
    match (irt, expect.in_response_to) {
        (Some(got), Some(want)) if got == want => {}
        (None, None) => {}
        _ if crate::mutants::on("saml-in-response-to") => {}
        _ => {
            return Err(bad(
                "inresponseto",
                "the assertion does not answer this login",
            ))
        }
    }
    // Conditions: window, audience, nothing unknown.
    let conditions = one(a, "Conditions")?;
    if let Some(end) = conditions.attribute("NotOnOrAfter") {
        let end = time(end).ok_or_else(|| bad("conditions", "invalid NotOnOrAfter"))?;
        if expect.now >= end.saturating_add(skew) && !crate::mutants::on("saml-expiry") {
            return Err(bad("conditions", "the assertion has expired"));
        }
    }
    if let Some(start) = conditions.attribute("NotBefore") {
        let start = time(start).ok_or_else(|| bad("conditions", "invalid NotBefore"))?;
        if expect.now < start.saturating_sub(skew) && !crate::mutants::on("saml-not-before") {
            return Err(bad("conditions", "the assertion is not yet valid"));
        }
    }
    let mut restrictions = 0;
    for condition in conditions.children().filter(Node::is_element) {
        if is_el(condition, SAML, "AudienceRestriction") {
            restrictions += 1;
            let accepted = child_els(condition, SAML, "Audience").any(|aud| {
                expect
                    .audiences
                    .iter()
                    .any(|ours| *ours == xml::text_of(aud))
            });
            if !accepted && !crate::mutants::on("saml-audience") {
                return Err(bad("audience", "the assertion is not for this SP"));
            }
        } else if !is_el(condition, SAML, "OneTimeUse") {
            return Err(bad("conditions", "unknown condition"));
        }
    }
    if restrictions == 0 && !crate::mutants::on("saml-audience") {
        return Err(bad(
            "audience",
            "the assertion carries no audience restriction",
        ));
    }
    let statement = child_els(a, SAML, "AuthnStatement").next();
    let Some(statement) = statement else {
        return Err(bad("structure", "no AuthnStatement"));
    };
    if let Some(end) = statement.attribute("SessionNotOnOrAfter") {
        let end = time(end).ok_or_else(|| bad("conditions", "invalid SessionNotOnOrAfter"))?;
        if expect.now >= end.saturating_add(skew) && !crate::mutants::on("saml-expiry") {
            return Err(bad("conditions", "the IdP session has ended"));
        }
    }
    let mut attributes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut total = 0usize;
    for statement in child_els(a, SAML, "AttributeStatement") {
        for attribute in child_els(statement, SAML, "Attribute") {
            let Some(name) = attribute.attribute("Name") else {
                continue;
            };
            for value in child_els(attribute, SAML, "AttributeValue") {
                if value.children().any(|c| c.is_element()) {
                    continue;
                }
                let text = xml::text_of(value);
                total += 1;
                if total > 1000 || text.len() > 4096 {
                    return Err(bad("structure", "attribute statement too large"));
                }
                attributes.entry(name.to_owned()).or_default().push(text);
            }
            if attributes.len() > 200 {
                return Err(bad("structure", "too many attributes"));
            }
        }
    }
    Ok(Claims {
        assertion_id: id.to_owned(),
        name_id,
        in_response_to: irt.map(str::to_owned),
        not_on_or_after: scd_end,
        attributes,
    })
}
