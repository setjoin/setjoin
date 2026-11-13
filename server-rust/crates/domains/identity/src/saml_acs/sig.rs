//! XML-DSig verification for the one shape a SAML Response uses: an enveloped
//! signature over its parent element, referenced by `#ID`, exclusive C14N, SHA-2,
//! RSA PKCS#1 v1.5 or ECDSA, verified with the *pinned* key only.
//!
//! Cryptography is ring (signatures) and sha2 (digests); canonicalization is
//! bergshamra-c14n. What a caller may consume is exactly the canonical bytes whose
//! digest was verified, re-parsed: the element that was signed *is* the element that
//! is read, whichever way the surrounding document was rearranged.
use super::pin::PinnedKey;
use super::xml::{self, child_els, is_el, Twin, DS, EXC, SAML, SAMLP};
use super::Fail;
use base64::{engine::general_purpose::STANDARD, Engine};
use bergshamra_c14n::{canonicalize_doc, C14nMode};
use bergshamra_xml::{uppsala, NodeSet};
use roxmltree::{Document, Node};
use sha2::{Digest, Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq;

const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
const SHA512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";
const SHA1_DIGEST: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const RSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
const RSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
const RSA_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
const ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
const ECDSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";

/// What a verified message yields: the canonical bytes of the signed element.
pub struct Verified {
    pub canonical: String,
    /// The consumed element is the Response (so its own attributes are signed).
    pub response_signed: bool,
}

#[derive(Clone, Copy, PartialEq)]
enum Hash {
    S256,
    S384,
    S512,
}
#[derive(Clone, Copy, PartialEq)]
enum Alg {
    Rsa(Hash),
    P256,
    P384,
}

fn fail(class: &'static str, detail: &'static str) -> Fail {
    Fail::new(class, detail)
}

/// Verify the message against the pinned keys and return the signed element.
pub fn verify(raw: &str, keys: &[PinnedKey]) -> Result<Verified, Fail> {
    let doc = xml::parse(raw)?;
    xml::refuse_comments(&doc)?;
    let ids = xml::ids(&doc)?;
    let root = doc.root_element();
    if !is_el(root, SAMLP, "Response") {
        return Err(fail("structure", "the document is not a SAML Response"));
    }
    if doc
        .descendants()
        .any(|n| is_el(n, SAML, "EncryptedAssertion") || is_el(n, SAML, "EncryptedID"))
    {
        return Err(fail("structure", "encrypted assertions are not supported"));
    }
    let assertions: Vec<_> = doc
        .descendants()
        .filter(|n| is_el(*n, SAML, "Assertion"))
        .collect();
    if assertions.len() != 1 && !crate::mutants::on("saml-wrapping") {
        return Err(fail("structure", "exactly one Assertion is required"));
    }
    let assertion = *assertions
        .first()
        .ok_or_else(|| fail("structure", "no Assertion"))?;
    if assertion.parent() != Some(root) && !crate::mutants::on("saml-wrapping") {
        return Err(fail(
            "structure",
            "the Assertion is not a child of the Response",
        ));
    }
    // Every Signature must sit where a signature may: child of the Response or of
    // its Assertion. A signature anywhere else is a wrapping artefact.
    let signatures: Vec<_> = doc
        .descendants()
        .filter(|n| is_el(*n, DS, "Signature"))
        .collect();
    let response_sig: Vec<_> = child_els(root, DS, "Signature").collect();
    let assertion_sig: Vec<_> = child_els(assertion, DS, "Signature").collect();
    if (response_sig.len() > 1
        || assertion_sig.len() > 1
        || signatures.len() != response_sig.len() + assertion_sig.len())
        && !crate::mutants::on("saml-wrapping")
    {
        return Err(fail("structure", "misplaced or repeated Signature"));
    }
    if signatures.is_empty() {
        if crate::mutants::on("saml-unsigned-ok") {
            return Ok(Verified {
                canonical: raw.to_owned(),
                response_signed: true,
            });
        }
        return Err(fail("unsigned", "the message carries no signature"));
    }
    let twin = Twin::new(raw, &doc)?;
    let mut consumed: Option<(String, bool)> = None;
    // Response first: when both are signed, the Response bytes (which contain the
    // Assertion) are what is consumed; the other signature must still verify.
    for sig in response_sig.iter().chain(assertion_sig.iter()) {
        let (target, canonical) = verify_signature(&doc, &twin, &ids, *sig, keys)?;
        if consumed.is_none() && (target == root.id() || target == assertion.id()) {
            consumed = Some((canonical, target == root.id()));
        }
    }
    consumed
        .map(|(canonical, response_signed)| Verified {
            canonical,
            response_signed,
        })
        .ok_or_else(|| fail("structure", "no signed Response or Assertion"))
}

#[derive(PartialEq)]
struct SignedInfo {
    c14n_prefixes: Vec<String>,
    alg: Alg,
    reference_prefixes: Vec<String>,
    digest: Hash,
    digest_value: Vec<u8>,
    target_id: String,
}

fn prefix_list(method: Node<'_, '_>) -> Result<Vec<String>, Fail> {
    let mut out = Vec::new();
    for child in method.children().filter(Node::is_element) {
        if !is_el(child, EXC, "InclusiveNamespaces") {
            return Err(fail(
                "algorithm",
                "unexpected child of a canonicalization method",
            ));
        }
        out.extend(
            child
                .attribute("PrefixList")
                .unwrap_or("")
                .split_ascii_whitespace()
                .map(str::to_owned),
        );
    }
    Ok(out)
}

fn exactly_one<'a, 'i>(node: Node<'a, 'i>, local: &'a str) -> Result<Node<'a, 'i>, Fail> {
    let mut it = child_els(node, DS, local);
    match (it.next(), it.next()) {
        (Some(one), None) => Ok(one),
        _ => Err(fail("structure", "malformed Signature structure")),
    }
}

fn signed_info(si: Node<'_, '_>) -> Result<SignedInfo, Fail> {
    if si.children().filter(Node::is_element).count() != 3 {
        return Err(fail(
            "structure",
            "SignedInfo must hold one method pair and one Reference",
        ));
    }
    let canon = exactly_one(si, "CanonicalizationMethod")?;
    if canon.attribute("Algorithm") != Some(EXC) {
        return Err(fail(
            "algorithm",
            "only exclusive canonicalization is accepted",
        ));
    }
    let c14n_prefixes = prefix_list(canon)?;
    let method = exactly_one(si, "SignatureMethod")?;
    let alg = match method.attribute("Algorithm").unwrap_or("") {
        RSA_SHA256 => Alg::Rsa(Hash::S256),
        RSA_SHA384 => Alg::Rsa(Hash::S384),
        RSA_SHA512 => Alg::Rsa(Hash::S512),
        ECDSA_SHA256 => Alg::P256,
        ECDSA_SHA384 => Alg::P384,
        RSA_SHA1 if crate::mutants::on("saml-sha1") => Alg::Rsa(Hash::S256),
        _ => return Err(fail("algorithm", "unsupported or weak signature algorithm")),
    };
    let reference = exactly_one(si, "Reference")?;
    let uri = reference.attribute("URI").unwrap_or("");
    let target_id = uri
        .strip_prefix('#')
        .filter(|s| !s.is_empty())
        .ok_or_else(|| fail("structure", "the Reference must name an element by ID"))?
        .to_owned();
    let transforms = exactly_one(reference, "Transforms")?;
    let list: Vec<_> = child_els(transforms, DS, "Transform").collect();
    if transforms.children().filter(Node::is_element).count() != list.len() || list.len() != 2 {
        return Err(fail(
            "algorithm",
            "the Reference must be enveloped-signature then exclusive C14N",
        ));
    }
    if list[0].attribute("Algorithm") != Some(ENVELOPED)
        || list[0].children().any(|c| c.is_element())
    {
        return Err(fail(
            "algorithm",
            "the first transform must be enveloped-signature",
        ));
    }
    if list[1].attribute("Algorithm") != Some(EXC) {
        return Err(fail(
            "algorithm",
            "the second transform must be exclusive C14N",
        ));
    }
    let reference_prefixes = prefix_list(list[1])?;
    let digest_method = exactly_one(reference, "DigestMethod")?;
    let digest = match digest_method.attribute("Algorithm").unwrap_or("") {
        SHA256 => Hash::S256,
        SHA384 => Hash::S384,
        SHA512 => Hash::S512,
        SHA1_DIGEST if crate::mutants::on("saml-sha1") => Hash::S256,
        _ => return Err(fail("algorithm", "unsupported or weak digest algorithm")),
    };
    let value = exactly_one(reference, "DigestValue")?;
    let digest_value = decode_b64(&xml::text_of(value))?;
    if reference.children().filter(Node::is_element).count() != 3 {
        return Err(fail("structure", "unexpected content in the Reference"));
    }
    Ok(SignedInfo {
        c14n_prefixes,
        alg,
        reference_prefixes,
        digest,
        digest_value,
        target_id,
    })
}

fn canonical_info(bytes: &[u8]) -> Result<SignedInfo, Fail> {
    let text = std::str::from_utf8(bytes).map_err(|_| fail("malformed", "canonical SignedInfo is not UTF-8"))?;
    let doc = xml::parse(text)?;
    signed_info(doc.root_element())
}

fn agree(structural: &SignedInfo, covered: &SignedInfo) -> Result<(), Fail> {
    if structural != covered && !crate::mutants::on("saml-signedinfo-raw") {
        return Err(fail("structure", "SignedInfo reads differently in the signed bytes"));
    }
    Ok(())
}

/// Test seam: does the structural reading of the first `ds:SignedInfo` in `raw` agree with
/// the verified canonical SignedInfo bytes?
pub fn signed_info_agreement(raw: &str, canonical: &str) -> Result<(), Fail> {
    let doc = xml::parse(raw)?;
    let node = doc
        .descendants()
        .find(|n| is_el(*n, DS, "SignedInfo"))
        .ok_or_else(|| fail("structure", "no SignedInfo"))?;
    agree(&signed_info(node)?, &canonical_info(canonical.as_bytes())?)
}

fn decode_b64(text: &str) -> Result<Vec<u8>, Fail> {
    let clean: String = text.split_ascii_whitespace().collect();
    STANDARD
        .decode(clean.as_bytes())
        .map_err(|_| fail("malformed", "invalid base64"))
}

fn verify_signature(
    doc: &Document<'_>,
    twin: &Twin<'_>,
    ids: &std::collections::HashMap<&str, Node<'_, '_>>,
    sig: Node<'_, '_>,
    keys: &[PinnedKey],
) -> Result<(roxmltree::NodeId, String), Fail> {
    let info_node = exactly_one(sig, "SignedInfo")?;
    let value_node = exactly_one(sig, "SignatureValue")?;
    // KeyInfo is accepted and ignored: the key is the pinned one. Object is not
    // accepted, since a Reference must never reach it.
    for child in sig.children().filter(Node::is_element) {
        let known = is_el(child, DS, "SignedInfo")
            || is_el(child, DS, "SignatureValue")
            || is_el(child, DS, "KeyInfo");
        if !known {
            return Err(fail("structure", "unexpected child of Signature"));
        }
    }
    let info = signed_info(info_node)?;
    // Resolve the URI to the element that this signature envelopes, exactly.
    let target = *ids
        .get(info.target_id.as_str())
        .ok_or_else(|| fail("structure", "the Reference names no element"))?;
    let parent = sig
        .parent()
        .ok_or_else(|| fail("structure", "orphan Signature"))?;
    if target != parent && !crate::mutants::on("saml-reference-uri") {
        return Err(fail(
            "structure",
            "the Reference does not name the enveloping element",
        ));
    }
    let utarget = twin
        .node(doc, target)
        .ok_or_else(|| fail("structure", "cannot locate the signed element"))?;
    let usig = twin
        .node(doc, sig)
        .ok_or_else(|| fail("structure", "cannot locate the Signature"))?;
    let uinfo = twin
        .node(doc, info_node)
        .ok_or_else(|| fail("structure", "cannot locate SignedInfo"))?;
    let signed = canonical_of(&twin.udoc, uinfo, None, &info.c14n_prefixes)?;
    let signature = decode_b64(&xml::text_of(value_node))?;
    let mut trusted = keys.to_vec();
    if crate::mutants::on("saml-keyinfo-trusted") {
        // Restored defect: believe the certificate the message itself carries.
        for node in sig
            .descendants()
            .filter(|n| is_el(*n, DS, "X509Certificate"))
        {
            trusted.extend(super::pin::parse(&xml::text_of(node)));
        }
    }
    if !signature_valid(info.alg, &trusted, &signed, &signature)
        && !crate::mutants::on("saml-signature-unchecked")
    {
        return Err(fail(
            "signature",
            "signature does not verify under the pinned key",
        ));
    }
    // What the signature covers is the canonical SignedInfo; the algorithms, the Reference
    // and the digest value that are *used* must be what those verified bytes say, however
    // the structural view of the message read them.
    let covered = canonical_info(&signed)?;
    agree(&info, &covered)?;
    let canonical = canonical_of(&twin.udoc, utarget, Some(usig), &covered.reference_prefixes)?;
    let digest = match covered.digest {
        Hash::S256 => Sha256::digest(&canonical).to_vec(),
        Hash::S384 => Sha384::digest(&canonical).to_vec(),
        Hash::S512 => Sha512::digest(&canonical).to_vec(),
    };
    if !bool::from(digest.ct_eq(&covered.digest_value)) && !crate::mutants::on("saml-digest-unchecked")
    {
        return Err(fail("signature", "digest mismatch"));
    }
    let text = String::from_utf8(canonical)
        .map_err(|_| fail("malformed", "canonical form is not UTF-8"))?;
    Ok((target.id(), text))
}

/// Exclusive C14N (no comments) of the subtree at `node`, with `excluded` (the
/// signature being verified, enveloped-signature transform) and all it contains
/// left out. The one canonicalization call every digest and signature input uses.
fn canonical_of(
    udoc: &uppsala::Document<'_>,
    node: uppsala::NodeId,
    excluded: Option<uppsala::NodeId>,
    prefixes: &[String],
) -> Result<Vec<u8>, Fail> {
    let mut set = NodeSet::tree_without_comments(node, udoc);
    if let Some(excluded) = excluded {
        remove_subtree(udoc, excluded, &mut set);
    }
    canonicalize_doc(udoc, C14nMode::Exclusive, Some(&set), prefixes)
        .map_err(|_| fail("malformed", "canonicalization failed"))
}

/// Exclusive canonical form of the first element named `{ns}local`; used by the
/// vector tests, which pin this implementation to the published examples.
pub fn canonical_element(
    text: &str,
    ns: &str,
    local: &str,
    prefixes: &[String],
) -> Result<String, Fail> {
    let doc = xml::parse(text)?;
    let twin = Twin::new(text, &doc)?;
    let node = doc
        .descendants()
        .find(|n| {
            n.is_element()
                && n.tag_name().name() == local
                && n.tag_name().namespace().filter(|s| !s.is_empty())
                    == Some(ns).filter(|s| !s.is_empty())
        })
        .ok_or_else(|| fail("structure", "no such element"))?;
    let unode = twin
        .node(&doc, node)
        .ok_or_else(|| fail("structure", "cannot locate"))?;
    let bytes = canonical_of(&twin.udoc, unode, None, prefixes)?;
    String::from_utf8(bytes).map_err(|_| fail("malformed", "not UTF-8"))
}

/// The enveloped-signature transform: the signature being verified, with all it
/// contains, is outside the digested node set.
fn remove_subtree(doc: &uppsala::Document<'_>, id: uppsala::NodeId, set: &mut NodeSet) {
    set.remove_id(id);
    for child in doc.children(id) {
        remove_subtree(doc, child, set);
    }
}

fn signature_valid(alg: Alg, keys: &[PinnedKey], message: &[u8], signature: &[u8]) -> bool {
    use ring::signature as s;
    keys.iter().any(|key| match (alg, key) {
        (Alg::Rsa(hash), PinnedKey::Rsa(der)) => {
            let params: &'static s::RsaParameters = match hash {
                Hash::S256 if crate::mutants::on("saml-weak-rsa") => {
                    &s::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY
                }
                Hash::S256 => &s::RSA_PKCS1_2048_8192_SHA256,
                Hash::S384 => &s::RSA_PKCS1_2048_8192_SHA384,
                Hash::S512 => &s::RSA_PKCS1_2048_8192_SHA512,
            };
            s::UnparsedPublicKey::new(params, der)
                .verify(message, signature)
                .is_ok()
        }
        (Alg::P256, PinnedKey::P256(point)) => {
            s::UnparsedPublicKey::new(&s::ECDSA_P256_SHA256_FIXED, point)
                .verify(message, signature)
                .is_ok()
        }
        (Alg::P384, PinnedKey::P384(point)) => {
            s::UnparsedPublicKey::new(&s::ECDSA_P384_SHA384_FIXED, point)
                .verify(message, signature)
                .is_ok()
        }
        _ => false,
    })
}
