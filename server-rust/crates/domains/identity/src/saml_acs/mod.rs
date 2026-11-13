//! Verified SAML 2.0 Assertion Consumer Service (#546, owner decision on #534).
//!
//! Pure verification, no I/O: [`process`] turns a decoded SAMLResponse into
//! [`Claims`] only if a pinned key signed the element the claims are read from.
//! Replay, provisioning and session minting stay in the callers.
mod assertion;
mod pin;
mod sig;
pub mod xml;

pub use assertion::{claims, time, Claims, Expect, SKEW};
pub use pin::{parse as parse_pins, PinnedKey};
pub use sig::{canonical_element, signed_info_agreement};

/// A refusal: `class` names the audit row (`saml.acs.<class>`); `detail` is for logs
/// and tests and is never sent to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fail {
    pub class: &'static str,
    pub detail: &'static str,
}
impl Fail {
    pub fn new(class: &'static str, detail: &'static str) -> Self {
        Self { class, detail }
    }
}

/// Verify the message and apply every check; `xml` is the already base64-decoded body.
pub fn process(xml_bytes: &[u8], keys: &[PinnedKey], expect: &Expect<'_>) -> Result<Claims, Fail> {
    if xml_bytes.len() > xml::MAX_XML && !crate::mutants::on("saml-xml-uncapped") {
        return Err(Fail::new("oversize", "XML exceeds the size cap"));
    }
    let text =
        std::str::from_utf8(xml_bytes).map_err(|_| Fail::new("malformed", "XML is not UTF-8"))?;
    if keys.is_empty() {
        return Err(Fail::new(
            "no_pinned_key",
            "the registration has no usable pinned key",
        ));
    }
    let verified = sig::verify(text, keys)?;
    let signed = claims_from(&verified.canonical, expect)?;
    if !verified.response_signed {
        // The Response wrapper is unsigned, so nothing it says is trusted; a
        // contradiction is still a refusal.
        let doc = xml::parse(text)?;
        let root = doc.root_element();
        // Unsigned, so only ever a refusal: an IdP that reports failure is not a login.
        let status = root
            .children()
            .find(|c| xml::is_el(*c, xml::SAMLP, "Status"))
            .and_then(|s| s.children().find(|c| xml::is_el(*c, xml::SAMLP, "StatusCode")))
            .and_then(|c| c.attribute("Value"));
        if status != Some("urn:oasis:names:tc:SAML:2.0:status:Success")
            && !crate::mutants::on("saml-status")
        {
            return Err(Fail::new("status", "the IdP did not report success"));
        }
        if root
            .attribute("Destination")
            .is_some_and(|d| d != expect.acs_url)
            && !crate::mutants::on("saml-destination")
        {
            return Err(Fail::new("destination", "Destination is not this ACS"));
        }
        assertion::check_response_irt(root, expect)?;
    }
    Ok(signed)
}

fn claims_from(canonical: &str, expect: &Expect<'_>) -> Result<Claims, Fail> {
    claims(canonical, expect)
}
