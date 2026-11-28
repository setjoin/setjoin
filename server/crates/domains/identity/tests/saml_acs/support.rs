//! Test-only SAML IdP: synthetic keys, assertion builder, XML-DSig signer.
//! Shared by the identity library tests and the auth HTTP tests (`#[path]`).
#![allow(dead_code)]
use base64::{engine::general_purpose::STANDARD, Engine};
use bergshamra_c14n::{canonicalize_doc, C14nMode};
use bergshamra_xml::{uppsala, NodeSet};
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
    sign::Signer,
    x509::{X509Builder, X509NameBuilder},
};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::sync::OnceLock;

pub const IDP: &str = "https://idp.example.test/metadata";
pub const AUD: &str = "https://sp.example.test/saml/metadata";
pub const ACS: &str =
    "https://sp.example.test/auth/saml/https:%2F%2Fidp.example.test%2Fmetadata/acs";
pub const REQUEST: &str = "id-0123456789abcdef";
pub const NOW: i64 = 1_800_000_000;

pub struct Idp {
    pub key: PKey<Private>,
    pub cert_pem: String,
}
fn make(key: PKey<Private>) -> Idp {
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "synthetic idp").unwrap();
    let name = name.build();
    let mut b = X509Builder::new().unwrap();
    b.set_version(2).unwrap();
    b.set_serial_number(&BigNum::from_u32(7).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(3650).unwrap())
        .unwrap();
    b.sign(&key, MessageDigest::sha256()).unwrap();
    let cert_pem = String::from_utf8(b.build().to_pem().unwrap()).unwrap();
    Idp { key, cert_pem }
}
pub fn rsa_idp() -> &'static Idp {
    static K: OnceLock<Idp> = OnceLock::new();
    K.get_or_init(|| make(PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap()))
}
pub fn rsa_attacker() -> &'static Idp {
    static K: OnceLock<Idp> = OnceLock::new();
    K.get_or_init(|| make(PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap()))
}
pub fn rsa1024() -> &'static Idp {
    static K: OnceLock<Idp> = OnceLock::new();
    K.get_or_init(|| make(PKey::from_rsa(Rsa::generate(1024).unwrap()).unwrap()))
}
pub fn ec256() -> &'static Idp {
    static K: OnceLock<Idp> = OnceLock::new();
    K.get_or_init(|| {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        make(PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap())
    })
}
pub fn ec384() -> &'static Idp {
    static K: OnceLock<Idp> = OnceLock::new();
    K.get_or_init(|| {
        let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
        make(PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap())
    })
}

#[derive(Clone, Copy, PartialEq)]
pub enum Sig {
    Rsa256,
    Rsa384,
    Rsa512,
    RsaSha1,
    Ec256,
    Ec384,
}
#[derive(Clone, Copy, PartialEq)]
pub enum Dig {
    S1,
    S256,
    S384,
    S512,
}
pub struct SigSpec<'a> {
    pub idp: &'a Idp,
    pub sig: Sig,
    pub dig: Dig,
    /// Embed this certificate in KeyInfo (the verifier must ignore it).
    pub key_info: Option<&'a str>,
    pub c14n_prefixes: &'a str,
}
impl<'a> SigSpec<'a> {
    pub fn new(idp: &'a Idp) -> Self {
        let sig = if idp.cert_pem == ec256().cert_pem {
            Sig::Ec256
        } else if idp.cert_pem == ec384().cert_pem {
            Sig::Ec384
        } else {
            Sig::Rsa256
        };
        Self {
            idp,
            sig,
            dig: Dig::S256,
            key_info: Some(&idp.cert_pem),
            c14n_prefixes: "",
        }
    }
}

pub struct Opts {
    pub issuer: String,
    pub name_id: String,
    pub name_id_format: Option<String>,
    pub audience: String,
    pub recipient: String,
    pub destination: String,
    pub irt: Option<String>,
    pub not_before: i64,
    pub not_on_or_after: i64,
    pub scd_not_on_or_after: i64,
    pub bearer: bool,
    pub attrs: Vec<(String, Vec<String>)>,
    pub assertion_id: String,
    pub response_id: String,
}
impl Default for Opts {
    fn default() -> Self {
        Self {
            issuer: IDP.into(),
            name_id: "alice-subject-1".into(),
            name_id_format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".into()),
            audience: AUD.into(),
            recipient: ACS.into(),
            destination: ACS.into(),
            irt: Some(REQUEST.into()),
            not_before: NOW - 30,
            not_on_or_after: NOW + 300,
            scd_not_on_or_after: NOW + 300,
            bearer: true,
            attrs: vec![
                ("email".into(), vec!["alice@example.test".into()]),
                ("memberOf".into(), vec!["staff".into(), "admins".into()]),
            ],
            assertion_id: "_assertion1".into(),
            response_id: "_response1".into(),
        }
    }
}
pub fn instant(t: i64) -> String {
    chrono::DateTime::from_timestamp(t, 0)
        .unwrap()
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}
pub fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
/// An Assertion element (no namespace declarations: it inherits the Response's).
pub fn assertion(o: &Opts, signature: &str) -> String {
    let fmt = o
        .name_id_format
        .as_ref()
        .map(|f| format!(" Format=\"{}\"", esc(f)))
        .unwrap_or_default();
    let irt = o
        .irt
        .as_ref()
        .map(|i| format!(" InResponseTo=\"{}\"", esc(i)))
        .unwrap_or_default();
    let method = if o.bearer {
        "urn:oasis:names:tc:SAML:2.0:cm:bearer"
    } else {
        "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"
    };
    let attrs: String = o
        .attrs
        .iter()
        .map(|(n, vs)| {
            format!(
                "<saml:Attribute Name=\"{}\">{}</saml:Attribute>",
                esc(n),
                vs.iter()
                    .map(|v| format!("<saml:AttributeValue>{}</saml:AttributeValue>", esc(v)))
                    .collect::<String>()
            )
        })
        .collect();
    format!(
        "<saml:Assertion ID=\"{id}\" Version=\"2.0\" IssueInstant=\"{iat}\"><saml:Issuer>{iss}</saml:Issuer>{signature}<saml:Subject><saml:NameID{fmt}>{name}</saml:NameID><saml:SubjectConfirmation Method=\"{method}\"><saml:SubjectConfirmationData{irt} NotOnOrAfter=\"{scd}\" Recipient=\"{rcp}\"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore=\"{nb}\" NotOnOrAfter=\"{na}\"><saml:AudienceRestriction><saml:Audience>{aud}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant=\"{iat}\"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement>{attrs}</saml:AttributeStatement></saml:Assertion>",
        id = esc(&o.assertion_id),
        iat = instant(NOW - 30),
        iss = esc(&o.issuer),
        name = esc(&o.name_id),
        scd = instant(o.scd_not_on_or_after),
        rcp = esc(&o.recipient),
        nb = instant(o.not_before),
        na = instant(o.not_on_or_after),
        aud = esc(&o.audience),
    )
}
pub fn response(o: &Opts, signature: &str, inner: &str) -> String {
    let irt = o
        .irt
        .as_ref()
        .map(|i| format!(" InResponseTo=\"{}\"", esc(i)))
        .unwrap_or_default();
    format!(
        "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"{id}\" Version=\"2.0\" IssueInstant=\"{iat}\" Destination=\"{dst}\"{irt}><saml:Issuer>{iss}</saml:Issuer>{signature}<samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>{inner}</samlp:Response>",
        id = esc(&o.response_id),
        iat = instant(NOW - 30),
        dst = esc(&o.destination),
        iss = esc(&o.issuer),
    )
}
/// A ds:Signature template over `target_id`; placeholders `@@D{n}@@`/`@@S{n}@@`.
pub fn template(n: usize, target_id: &str, spec: &SigSpec<'_>) -> String {
    let (sigm, _) = match spec.sig {
        Sig::Rsa256 => ("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", 0),
        Sig::Rsa384 => ("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", 0),
        Sig::Rsa512 => ("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", 0),
        Sig::RsaSha1 => ("http://www.w3.org/2000/09/xmldsig#rsa-sha1", 0),
        Sig::Ec256 => ("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", 0),
        Sig::Ec384 => ("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384", 0),
    };
    let dig = match spec.dig {
        Dig::S1 => "http://www.w3.org/2000/09/xmldsig#sha1",
        Dig::S256 => "http://www.w3.org/2001/04/xmlenc#sha256",
        Dig::S384 => "http://www.w3.org/2001/04/xmldsig-more#sha384",
        Dig::S512 => "http://www.w3.org/2001/04/xmlenc#sha512",
    };
    let prefix = if spec.c14n_prefixes.is_empty() {
        String::new()
    } else {
        format!("<ec:InclusiveNamespaces xmlns:ec=\"http://www.w3.org/2001/10/xml-exc-c14n#\" PrefixList=\"{}\"/>", spec.c14n_prefixes)
    };
    let key_info = spec
        .key_info
        .map(|pem| {
            let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
            format!("<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{body}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>")
        })
        .unwrap_or_default();
    format!(
        "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"sig{n}\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\">{prefix}</ds:CanonicalizationMethod><ds:SignatureMethod Algorithm=\"{sigm}\"/><ds:Reference URI=\"#{target_id}\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\">{prefix}</ds:Transform></ds:Transforms><ds:DigestMethod Algorithm=\"{dig}\"/><ds:DigestValue>@@D{n}@@</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>@@S{n}@@</ds:SignatureValue>{key_info}</ds:Signature>"
    )
}

fn find(doc: &uppsala::Document<'_>, id: &str) -> uppsala::NodeId {
    doc.descendants(doc.root())
        .into_iter()
        .find(|n| {
            doc.element(*n)
                .is_some_and(|e| e.get_attribute("Id") == Some(id))
        })
        .expect("signature template present")
}
fn remove(doc: &uppsala::Document<'_>, id: uppsala::NodeId, set: &mut NodeSet) {
    set.remove_id(id);
    for c in doc.children(id) {
        remove(doc, c, set);
    }
}
fn raw_sign(spec: &SigSpec<'_>, data: &[u8]) -> Vec<u8> {
    let digest = match spec.sig {
        Sig::Rsa256 | Sig::Ec256 => MessageDigest::sha256(),
        Sig::Rsa384 | Sig::Ec384 => MessageDigest::sha384(),
        Sig::Rsa512 => MessageDigest::sha512(),
        Sig::RsaSha1 => MessageDigest::sha1(),
    };
    let mut signer = Signer::new(digest, &spec.idp.key).unwrap();
    signer.update(data).unwrap();
    let der = signer.sign_to_vec().unwrap();
    match spec.sig {
        Sig::Ec256 | Sig::Ec384 => {
            let size = if spec.sig == Sig::Ec256 { 32 } else { 48 };
            let s = EcdsaSig::from_der(&der).unwrap();
            let mut out = s.r().to_vec_padded(size).unwrap();
            out.extend(s.s().to_vec_padded(size).unwrap());
            out
        }
        _ => der,
    }
}
/// Fill signature `n` (digest, then signature value) in place.
pub fn sign(xml: &str, n: usize, spec: &SigSpec<'_>) -> String {
    let id = format!("sig{n}");
    let digest_marker = format!("@@D{n}@@");
    let doc = uppsala::parse(xml).unwrap();
    let sig = find(&doc, &id);
    let target = doc.parent(sig).unwrap();
    let mut set = NodeSet::tree_without_comments(target, &doc);
    remove(&doc, sig, &mut set);
    let prefixes: Vec<String> = spec
        .c14n_prefixes
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    let bytes = canonicalize_doc(&doc, C14nMode::Exclusive, Some(&set), &prefixes).unwrap();
    let digest = match spec.dig {
        Dig::S1 => {
            let mut h = openssl::hash::Hasher::new(MessageDigest::sha1()).unwrap();
            h.update(&bytes).unwrap();
            h.finish().unwrap().to_vec()
        }
        Dig::S256 => Sha256::digest(&bytes).to_vec(),
        Dig::S384 => Sha384::digest(&bytes).to_vec(),
        Dig::S512 => Sha512::digest(&bytes).to_vec(),
    };
    let xml = xml.replace(&digest_marker, &STANDARD.encode(digest));
    let doc = uppsala::parse(&xml).unwrap();
    let sig = find(&doc, &id);
    let info = doc
        .children(sig)
        .into_iter()
        .find(|c| {
            doc.element(*c)
                .is_some_and(|e| &*e.name.local_name == "SignedInfo")
        })
        .unwrap();
    let set = NodeSet::tree_without_comments(info, &doc);
    let signed = canonicalize_doc(&doc, C14nMode::Exclusive, Some(&set), &prefixes).unwrap();
    let value = STANDARD.encode(raw_sign(spec, &signed));
    xml.replace(&format!("@@S{n}@@"), &value)
}

/// The standard shapes. Each returns the message XML.
pub fn signed_assertion(o: &Opts, spec: &SigSpec<'_>) -> String {
    let a = assertion(o, &template(1, &o.assertion_id, spec));
    sign(&response(o, "", &a), 1, spec)
}
pub fn signed_response(o: &Opts, spec: &SigSpec<'_>) -> String {
    let a = assertion(o, "");
    sign(
        &response(o, &template(1, &o.response_id, spec), &a),
        1,
        spec,
    )
}
pub fn both_signed(o: &Opts, spec: &SigSpec<'_>) -> String {
    let a = assertion(o, &template(2, &o.assertion_id, spec));
    let xml = response(o, &template(1, &o.response_id, spec), &a);
    // The Response digest covers the (already signed) Assertion: sign inner first.
    sign(&sign(&xml, 2, spec), 1, spec)
}
pub fn unsigned(o: &Opts) -> String {
    response(o, "", &assertion(o, ""))
}
pub fn pins(idp: &Idp) -> Vec<setjoin_identity::saml_acs::PinnedKey> {
    setjoin_identity::saml_acs::parse_pins(&idp.cert_pem)
}
pub fn expect<'a>(audiences: &'a [String]) -> setjoin_identity::saml_acs::Expect<'a> {
    setjoin_identity::saml_acs::Expect {
        idp_entity_id: IDP,
        audiences,
        acs_url: ACS,
        in_response_to: Some(REQUEST),
        now: NOW,
    }
}
