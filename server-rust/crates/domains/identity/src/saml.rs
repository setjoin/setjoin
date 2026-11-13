//! Frozen Go SP profile. The registered ACS cannot reach assertion parsing;
//! this module grants no principal authority from inbound SAML XML.
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{json, Value};
use setjoin_pg::ScopedExecutor;
use std::{
    collections::BTreeMap,
    io::Write,
    sync::{Arc, RwLock},
};
pub const REDIRECT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
pub const POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
pub const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const MD: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
enum SpSigner {
    Ring(ring::signature::RsaKeyPair),
    Existing(openssl::pkey::PKey<openssl::pkey::Private>),
}
struct Key {
    signer: SpSigner,
    certificate: Vec<u8>,
}
impl Key {
    fn load(cert: &str, key: &str) -> Result<Self, String> {
        let key = openssl::pkey::PKey::private_key_from_pem(
            &std::fs::read(key).map_err(|_| "read SAML key")?,
        )
        .map_err(|_| "parse SAML key")?;
        let rsa = key.rsa().map_err(|_| "SAML private key is not RSA")?;
        let cert = openssl::x509::X509::from_pem(
            &std::fs::read(cert).map_err(|_| "read SAML certificate")?,
        )
        .map_err(|_| "parse SAML certificate")?;
        if !cert
            .public_key()
            .map_err(|_| "SAML public key")?
            .public_eq(&key)
        {
            return Err("SAML certificate/key mismatch".into());
        }
        let signer = match ring::signature::RsaKeyPair::from_der(
            &rsa.private_key_to_der().map_err(|_| "SAML key DER")?,
        ) {
            Ok(pair) => SpSigner::Ring(pair),
            Err(_) => SpSigner::Existing(key),
        };
        Ok(Self {
            signer,
            certificate: cert.to_der().map_err(|_| "SAML certificate DER")?,
        })
    }
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        match &self.signer {
            SpSigner::Ring(pair) => {
                let mut sig = vec![0; pair.public().modulus_len()];
                pair.sign(
                    &ring::signature::RSA_PKCS1_SHA256,
                    &SystemRandom::new(),
                    data,
                    &mut sig,
                )
                .map_err(|_| "SAML RSA signing failed")?;
                Ok(sig)
            }
            // Existing Go keys outside ring's supported profile must not force
            // a key rotation. Audited OpenSSL owns the complete legacy operation.
            SpSigner::Existing(key) => {
                if key.bits() < 1024 {
                    return Err("SAML RSA signing failed".into());
                }
                let mut signer =
                    openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), key)
                        .map_err(|_| "SAML signer")?;
                signer
                    .set_rsa_padding(openssl::rsa::Padding::PKCS1)
                    .map_err(|_| "SAML RSA padding")?;
                signer
                    .sign_oneshot_to_vec(data)
                    .map_err(|_| "SAML RSA signing failed".into())
            }
        }
    }
    fn jwt(&self, claims: Value) -> Result<String, String> {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        Ok(format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(self.sign(input.as_bytes())?)
        ))
    }
}
pub struct Registration {
    id: i64,
    root: String,
    /// The real ACS URL, `{root}/auth/saml/{idp}/acs` (#546): AuthnRequest target,
    /// tracking-cookie scope, Destination and Recipient.
    acs: url::Url,
    issuer: url::Url,
    destination: String,
    binding: String,
    key: Arc<Key>,
    entity: String,
    pins: Vec<crate::saml_acs::PinnedKey>,
    audiences: Vec<String>,
    jit: bool,
    idp_initiated: bool,
    group_attribute: String,
    attribute_map: BTreeMap<String, String>,
    mappings: Vec<crate::rp::Mapping>,
}
pub struct Registry {
    exec: ScopedExecutor,
    encryption_key: String,
    key: Arc<Key>,
    http: Arc<dyn crate::rp::Http>,
    entries: RwLock<BTreeMap<String, Arc<Registration>>>,
    reload: tokio::sync::Mutex<()>,
}
impl Registry {
    pub async fn load(
        exec: ScopedExecutor,
        cert: &str,
        key: &str,
        encryption_key: &str,
        http: Arc<dyn crate::rp::Http>,
    ) -> Result<Arc<Self>, String> {
        let cert = cert.to_owned();
        let key = key.to_owned();
        let key = tokio::task::spawn_blocking(move || Key::load(&cert, &key))
            .await
            .map_err(|_| "SAML key task")??;
        let registry = Arc::new(Self {
            exec,
            encryption_key: encryption_key.to_owned(),
            key: Arc::new(key),
            http,
            entries: RwLock::new(BTreeMap::new()),
            reload: tokio::sync::Mutex::new(()),
        });
        if let Err(error) = registry.reload().await {
            eprintln!("SAML registrations failed closed: {error}");
        }
        Ok(registry)
    }
    pub fn registration(&self, name: &str) -> Option<Arc<Registration>> {
        self.entries.read().unwrap().get(name).cloned()
    }
    pub async fn reload(&self) -> Result<(), String> {
        let _lock = self.reload.lock().await;
        let result = self.load_entries().await;
        match result {
            Ok((entries, errors)) => {
                *self.entries.write().unwrap() = entries;
                if errors.is_empty() {
                    Ok(())
                } else {
                    Err(errors.join("; "))
                }
            }
            Err(e) => {
                self.entries.write().unwrap().clear();
                Err(e)
            }
        }
    }
    async fn load_entries(
        &self,
    ) -> Result<(BTreeMap<String, Arc<Registration>>, Vec<String>), String> {
        // Deployment-owned registrations, not user data. Keep the full Go scan:
        // an SQL/decryption/type failure invalidates the complete snapshot.
        let rows=self.exec.read("SELECT id,idp_entity_id,idp_metadata_url,idp_sso_url,pgp_sym_decrypt(idp_cert_enc,$1::text),sp_entity_id,sp_acs_url,attribute_map::text,jit_enabled,enabled,group_attribute,group_mappings::text,allow_idp_initiated FROM saml_sp_registrations WHERE enabled=TRUE",&[(&self.encryption_key,setjoin_pg::Type::TEXT)]).await.map_err(|e|e.message)?;
        let mut entries = BTreeMap::new();
        let mut errors = Vec::new();
        for row in rows {
            let id: i64 = row.try_get(0).map_err(|_| "SAML registration ID")?;
            let name: String = row.try_get(1).map_err(|_| "SAML registration entity")?;
            let metadata: String = row.try_get(2).map_err(|_| "SAML registration metadata")?;
            for index in [3, 4, 6, 10] {
                row.try_get::<_, String>(index)
                    .map_err(|_| "SAML registration string")?;
            }
            let sp: String = row.try_get(5).map_err(|_| "SAML SP entity")?;
            let attributes: String = row.try_get(7).map_err(|_| "SAML attribute map")?;
            let attribute_map = serde_json::from_str::<Option<BTreeMap<String, String>>>(&attributes)
                .map_err(|_| "SAML attribute map type")?
                .unwrap_or_default();
            let cert_text: String = row.try_get(4).map_err(|_| "SAML registration string")?;
            let jit: bool = row.try_get(8).map_err(|_| "SAML JIT flag")?;
            let group_attribute: String = row.try_get(10).map_err(|_| "SAML registration string")?;
            let idp_initiated: bool = row.try_get(12).map_err(|_| "SAML IdP-initiated flag")?;
            let mappings: Option<String> = row.try_get(11).map_err(|_| "SAML group mappings")?;
            let build = async {
                let mappings: Option<Vec<SamlMapping>> =
                    serde_json::from_str(mappings.as_deref().unwrap_or("null"))
                        .map_err(|_| "invalid SAML group mappings")?;
                let full_mappings: Vec<crate::rp::Mapping> = mappings
                    .iter()
                    .flatten()
                    .map(SamlMapping::mapping)
                    .collect();
                if mappings.as_ref().is_some_and(|ms| {
                    ms.len() > 100
                        || ms.iter().any(|m| {
                            m.idp_group.trim().is_empty()
                                || m.idp_group.len() > 1024
                                || m.idp_group.chars().any(char::is_control)
                        })
                }) {
                    return Err("invalid SAML group mappings".to_owned());
                }
                let mut root = url::Url::parse(&sp).map_err(|_| "invalid SAML SP URL")?;
                root.set_path("");
                let root_text = format!(
                    "{}{}{}",
                    &root[..url::Position::BeforePath],
                    root.query().map(|q| format!("?{q}")).unwrap_or_default(),
                    root.fragment().map(|f| format!("#{f}")).unwrap_or_default()
                );
                let bindings = match parse_metadata(&metadata) {
                    Ok(bindings) => bindings,
                    Err(_) => {
                        let url =
                            url::Url::parse(&metadata).map_err(|_| "invalid SAML metadata")?;
                        if (url.scheme() != "https" && !crate::mutants::on("saml-metadata-http"))
                            || url.host_str().is_none()
                        {
                            return Err("SAML metadata requires https".into());
                        }
                        // A literal private address is refused before any transport
                        // is asked, whatever transport an embedding supplies.
                        if !crate::mutants::on("saml-metadata-ssrf")
                            && url
                                .host_str()
                                .and_then(|h| h.trim_matches(['[', ']']).parse().ok())
                                .is_some_and(setjoin_authz::ssrf::blocked)
                        {
                            return Err("SAML metadata destination is not public".into());
                        }
                        let request = openidconnect::http::Request::builder()
                            .uri(url.as_str())
                            .body(Vec::new())
                            .map_err(|_| "SAML metadata request")?;
                        let response = self
                            .http
                            .send(request)
                            .await
                            .map_err(|_| "SAML metadata fetch")?;
                        if response.status().as_u16() >= 400 {
                            return Err("SAML metadata status".into());
                        }
                        // The 1 MiB cap holds for any transport an embedding supplies.
                        if response.body().len() > crate::rp::MAX_IDP_BODY
                            && !crate::mutants::on("saml-metadata-uncapped")
                        {
                            return Err("SAML metadata too large".into());
                        }
                        parse_metadata(
                            std::str::from_utf8(response.body())
                                .map_err(|_| "SAML metadata UTF-8")?,
                        )?
                    }
                };
                let (binding, destination) =
                    if let Some(v) = bindings.get(REDIRECT).filter(|s| !s.is_empty()) {
                        (REDIRECT, v.clone())
                    } else {
                        (POST, bindings.get(POST).cloned().unwrap_or_default())
                    };
                let issuer = root
                    .join("saml/metadata")
                    .map_err(|_| "SAML metadata URL")?;
                let mut acs = root.clone();
                acs.set_query(None);
                acs.set_fragment(None);
                acs.path_segments_mut()
                    .map_err(|_| "SAML ACS URL")?
                    .clear()
                    .extend(["auth", "saml", name.as_str(), "acs"]);
                Ok(Registration {
                    id,
                    root: root_text,
                    acs,
                    audiences: vec![issuer.as_str().to_owned(), sp.clone()],
                    issuer,
                    destination,
                    binding: binding.into(),
                    key: self.key.clone(),
                    entity: name.clone(),
                    pins: crate::saml_acs::parse_pins(&cert_text),
                    jit,
                    idp_initiated,
                    group_attribute,
                    attribute_map,
                    mappings: full_mappings,
                })
            }
            .await;
            match build {
                Ok(reg) => {
                    entries.insert(name, Arc::new(reg));
                }
                Err(e) => errors.push(e),
            }
        }
        Ok((entries, errors))
    }
}
fn parse_metadata(raw: &str) -> Result<BTreeMap<String, String>, String> {
    let doc = roxmltree::Document::parse(raw).map_err(|_| "invalid SAML metadata XML")?;
    let root = doc.root_element();
    let entity = if root.has_tag_name((MD, "EntityDescriptor")) {
        root
    } else if root.has_tag_name((MD, "EntitiesDescriptor")) {
        root.children()
            .find(|n| {
                n.has_tag_name((MD, "EntityDescriptor"))
                    && n.children()
                        .any(|n| n.has_tag_name((MD, "IDPSSODescriptor")))
            })
            .ok_or("no IdP entity")?
    } else {
        return Err("invalid metadata root".into());
    };
    let mut bindings = BTreeMap::new();
    for d in entity
        .children()
        .filter(|n| n.has_tag_name((MD, "IDPSSODescriptor")))
    {
        for s in d
            .children()
            .filter(|n| n.has_tag_name((MD, "SingleSignOnService")))
        {
            bindings
                .entry(s.attribute("Binding").unwrap_or("").to_owned())
                .or_insert_with(|| s.attribute("Location").unwrap_or("").to_owned());
        }
    }
    Ok(bindings)
}
fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
fn encoded(value: &str) -> String {
    form_urlencoded::byte_serialize(value.as_bytes()).collect()
}
pub struct Authorization {
    pub location: String,
    pub cookie: String,
    pub post: Option<String>,
}
impl Registration {
    pub fn key(&self) -> String {
        format!("saml:{}", self.id)
    }
    /// `purpose` is `login` or `link`; a link names the link flow it belongs to. Both and the
    /// registration id are SP-signed into the tracking JWT and verified at the ACS.
    pub fn authorization(&self, uri: &str, purpose: &str, flow: Option<&str>) -> Result<Authorization, String> {
        let mut id = [0; 20];
        let mut relay = [0; 42];
        SystemRandom::new()
            .fill(&mut id)
            .map_err(|_| "SAML request RNG")?;
        SystemRandom::new()
            .fill(&mut relay)
            .map_err(|_| "SAML relay RNG")?;
        let id = format!(
            "id-{}",
            id.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        let relay = URL_SAFE_NO_PAD.encode(relay);
        let now: chrono::DateTime<chrono::Utc> = std::time::SystemTime::now().into();
        let mut instant = now.format("%Y-%m-%dT%H:%M:%S").to_string();
        if now.timestamp_subsec_millis() != 0 {
            instant.push('.');
            instant.push_str(format!("{:03}", now.timestamp_subsec_millis()).trim_end_matches('0'));
        }
        instant.push('Z');
        let xml=format!("<samlp:AuthnRequest xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"{id}\" Version=\"2.0\" IssueInstant=\"{instant}\" Destination=\"{}\" AssertionConsumerServiceURL=\"{}\" ProtocolBinding=\"{POST}\"><saml:Issuer Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">{}</saml:Issuer><samlp:NameIDPolicy AllowCreate=\"true\"/></samlp:AuthnRequest>",escape(&self.destination),escape(self.acs.as_str()),escape(self.issuer.as_str()));
        let tracked=self.key.jwt(json!({"iss":self.root,"sub":relay,"aud":[self.root],"exp":now.timestamp()+90,"nbf":now.timestamp(),"iat":now.timestamp(),"id":id,"uri":uri,"saml-authn-request":true,"purpose":purpose,"reg":self.id,"flow":flow}))?;
        let cookie = format!(
            "saml_{relay}={tracked}; Path={}; Max-Age=90; HttpOnly; SameSite=None; Secure",
            self.acs.path()
        );
        if self.binding == POST {
            let xml = self.sign_post(&xml, &id)?;
            let action = if self.destination.split_once(':').is_some_and(|(scheme, _)| {
                !matches!(
                    scheme.to_ascii_lowercase().as_str(),
                    "http" | "https" | "mailto"
                )
            }) {
                "#ZgotmplZ"
            } else {
                &self.destination
            };
            let html=format!("<!DOCTYPE html><html><body><form method=\"post\" action=\"{}\" id=\"SAMLRequestForm\"><input type=\"hidden\" name=\"SAMLRequest\" value=\"{}\" /><input type=\"hidden\" name=\"RelayState\" value=\"{relay}\" /><input id=\"SAMLSubmitButton\" type=\"submit\" value=\"Submit\" /></form><script>document.getElementById('SAMLSubmitButton').style.visibility=\"hidden\";document.getElementById('SAMLRequestForm').submit();</script></body></html>",html_attribute(action),html_attribute(&STANDARD.encode(xml)));
            return Ok(Authorization {
                location: self.destination.clone(),
                cookie,
                post: Some(html),
            });
        }
        let mut zip = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
        zip.write_all(xml.as_bytes()).map_err(|_| "SAML deflate")?;
        let data = zip.finish().map_err(|_| "SAML deflate")?;
        let mut destination =
            url::Url::parse(&self.destination).map_err(|_| "SAML redirect URL")?;
        let prefix = destination
            .query()
            .filter(|s| !s.is_empty())
            .map(|s| format!("{s}&"))
            .unwrap_or_default();
        let signed = format!(
            "{prefix}SAMLRequest={}&RelayState={relay}&SigAlg={}",
            encoded(&STANDARD.encode(data)),
            encoded(RSA_SHA256)
        );
        destination.set_query(Some(&format!(
            "{signed}&Signature={}",
            encoded(&STANDARD.encode(self.key.sign(signed.as_bytes())?))
        )));
        Ok(Authorization {
            location: destination.to_string(),
            cookie,
            post: None,
        })
    }
}

fn html_attribute(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&#34;")
        .replace('\'', "&#39;")
        .replace('+', "&#43;")
}
struct RequestSigner(Arc<Key>);
impl kryptering::Signer for RequestSigner {
    fn algorithm(&self) -> kryptering::SignatureAlgorithm {
        kryptering::SignatureAlgorithm::RsaPkcs1v15(kryptering::HashAlgorithm::Sha256)
    }
    fn sign(&self, data: &[u8]) -> kryptering::Result<Vec<u8>> {
        self.0.sign(data).map_err(kryptering::Error::Crypto)
    }
}
impl Registration {
    fn sign_post(&self, xml: &str, id: &str) -> Result<String, String> {
        // All XML here is constructed by this profile, escaped before parsing.
        // The sole reference is this new request's ID, never a URL or file.
        let signature=format!("<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:SignatureMethod Algorithm=\"{RSA_SHA256}\"/><ds:Reference URI=\"#{id}\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>",STANDARD.encode(&self.key.certificate));
        let template = xml.replacen("</saml:Issuer>", &format!("</saml:Issuer>{signature}"), 1);
        let ctx = bergshamra_dsig::DsigContext::new(bergshamra_keys::KeysManager::new())
            .with_hsm_signer(Box::new(RequestSigner(self.key.clone())));
        bergshamra_dsig::sign::sign(&ctx, &template)
            .map_err(|e| format!("SAML request signature: {e}"))
    }
}

impl Registration {
    /// The SP-signed claims of a JWT this SP issued (tracking cookie or SP session),
    /// after its RS256 signature verifies under the SP key. Nothing else is checked.
    fn sp_jwt_claims(&self, raw: &str) -> Option<Value> {
        let parts: Vec<_> = raw.split('.').collect();
        if parts.len() != 3 {
            return None;
        }
        let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).ok()?).ok()?;
        if header["alg"] != "RS256" {
            return None;
        }
        let signature = URL_SAFE_NO_PAD.decode(parts[2]).ok()?;
        let input = format!("{}.{}", parts[0], parts[1]);
        if !crate::mutants::on("saml-tracking-unsigned") {
            match &self.key.signer {
                SpSigner::Ring(pair) => ring::signature::UnparsedPublicKey::new(
                    &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                    pair.public().as_ref(),
                )
                .verify(input.as_bytes(), &signature)
                .ok()?,
                SpSigner::Existing(key) => {
                    if key.bits() < 1024 {
                        return None;
                    }
                    let mut verifier =
                        openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha256(), key)
                            .ok()?;
                    verifier
                        .set_rsa_padding(openssl::rsa::Padding::PKCS1)
                        .ok()?;
                    if !verifier.verify_oneshot(&signature, input.as_bytes()).ok()? {
                        return None;
                    }
                }
            }
        }
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).ok()?).ok()
    }
    /// A pre-existing SP session can skip another IdP redirect. It never
    /// authorizes user data or creates a first-party identity credential.
    pub fn has_session(&self, raw: &str) -> bool {
        let check = || -> Option<()> {
            let claims = self.sp_jwt_claims(raw)?;
            if claims["iss"] != self.root
                || claims["aud"] != self.root
                || claims["saml-session"] != true
            {
                return None;
            }
            for name in ["iss", "aud", "sub", "jti"] {
                if claims
                    .get(name)
                    .is_some_and(|v| !v.is_null() && !v.is_string())
                {
                    return None;
                }
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()?
                .as_secs() as i64;
            for name in ["exp", "iat", "nbf"] {
                let value = match claims.get(name) {
                    None | Some(Value::Null) => 0,
                    Some(value) => value.as_i64()?,
                };
                if value != 0
                    && if name == "exp" {
                        now > value
                    } else {
                        now < value
                    }
                {
                    return None;
                }
            }
            if let Some(attributes) = claims.get("attr").filter(|v| !v.is_null()) {
                serde_json::from_value::<BTreeMap<String, Option<Vec<String>>>>(attributes.clone())
                    .ok()?;
            }
            Some(())
        };
        check().is_some()
    }
}

#[path = "saml_flow.rs"]
mod flow;
pub use flow::{audit, relay_target, valid_relay, Consumed, Tracking};
#[path = "saml_listener.rs"]
mod listener;
pub use listener::{admit_worker, Listener};

// These configuration structs use Go encoding/json's folded names and null
// no-op behavior; unknown fields are skipped without numeric conversion.
#[derive(Clone, Copy)]
enum ConfigType {
    Text,
    Integer,
}
struct GoConfig<'a>(&'a [(&'a str, ConfigType)]);
impl<'de> serde::de::DeserializeSeed<'de> for GoConfig<'_> {
    type Value = BTreeMap<String, Value>;
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        struct Object<'a>(&'a [(&'a str, ConfigType)]);
        impl<'de> serde::de::Visitor<'de> for Object<'_> {
            type Value = BTreeMap<String, Value>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("configuration object or null")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(BTreeMap::new())
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> Result<Self::Value, M::Error> {
                let mut out = BTreeMap::new();
                while let Some(name) = map.next_key::<String>()? {
                    let folded: String = name
                        .chars()
                        .map(|c| match c {
                            'ſ' => 's',
                            'K' => 'k',
                            c => c.to_ascii_lowercase(),
                        })
                        .collect();
                    if let Some((key, kind)) = self.0.iter().find(|(key, _)| *key == folded) {
                        let value = match kind {
                            ConfigType::Text => {
                                map.next_value::<Option<String>>()?.map(Value::String)
                            }
                            ConfigType::Integer => map
                                .next_value::<Option<i64>>()?
                                .map(|n| Value::Number(n.into())),
                        };
                        if let Some(value) = value {
                            out.insert((*key).into(), value);
                        }
                    } else {
                        map.next_value::<serde::de::IgnoredAny>()?;
                    }
                }
                Ok(out)
            }
        }
        d.deserialize_any(Object(self.0))
    }
}
struct SamlMapping {
    idp_group: String,
    distribution_group_id: Option<i64>,
    admin_role: Option<String>,
    department_id: Option<i64>,
}
impl SamlMapping {
    fn mapping(&self) -> crate::rp::Mapping {
        crate::rp::Mapping {
            idp_group: self.idp_group.clone(),
            distribution_group_id: self.distribution_group_id,
            admin_role: self.admin_role.clone(),
            department_id: self.department_id,
        }
    }
}
impl<'de> serde::Deserialize<'de> for SamlMapping {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::DeserializeSeed;
        let fields = GoConfig(&[
            ("idp_group", ConfigType::Text),
            ("distribution_group_id", ConfigType::Integer),
            ("admin_role", ConfigType::Text),
            ("department_id", ConfigType::Integer),
        ])
        .deserialize(d)?;
        Ok(Self {
            idp_group: fields
                .get("idp_group")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            distribution_group_id: fields.get("distribution_group_id").and_then(Value::as_i64),
            admin_role: fields.get("admin_role").and_then(Value::as_str).map(str::to_owned),
            department_id: fields.get("department_id").and_then(Value::as_i64),
        })
    }
}
fn config_change(raw: &str) -> Option<String> {
    use serde::de::DeserializeSeed;
    let mut d = serde_json::Deserializer::from_str(raw);
    let fields = GoConfig(&[("key", ConfigType::Text)])
        .deserialize(&mut d)
        .ok()?;
    d.end().ok()?;
    fields.get("key").and_then(Value::as_str).map(str::to_owned)
}
