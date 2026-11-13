//! Go PKCS#8/SPKI custody. ring owns the normal RS256 profile; unmodified
//! OpenSSL preserves valid pre-existing Go keys outside ring's key profile.
//! RustCrypto generates new2048-bit keys and never signs or decrypts.
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use rsa::pkcs8::EncodePrivateKey;
use openssl::{pkey::{PKey,Private,Id},hash::MessageDigest,rsa::Padding};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
};

enum Signer {Ring(ring::signature::RsaKeyPair),Legacy(PKey<Private>)}
pub struct SigningKey {
    pair: Signer,
    n: Vec<u8>,
    e: Vec<u8>,
    kid: String,
}
impl SigningKey {
    pub fn load(private_path: &str, public_path: &str) -> Result<Self, String> {
        let work = || -> Result<Self, Box<dyn std::error::Error>> {
            if private_path.is_empty() || public_path.is_empty() || private_path == public_path {
                return Err("OIDC key paths must be non-empty and distinct".into());
            }
            let (key, der) = match fs::read_to_string(private_path) {
                Ok(pem) => {
                    let der = decode_pem(&pem)?;
                    let key = parse_private(&der)?;
                    fs::set_permissions(private_path, fs::Permissions::from_mode(0o600))?;
                    (key, der)
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    let key = rsa::RsaPrivateKey::new(&mut rand::rng(), 2048)?;
                    let der = key.to_pkcs8_der()?.as_bytes().to_vec();
                    let mut f = fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(private_path)?;
                    if let Err(e) = f.write_all(pem("PRIVATE KEY", &der).as_bytes()) {
                        drop(f);
                        let _ = fs::remove_file(private_path);
                        return Err(e.into());
                    }
                    (parse_private(&der)?, der)
                }
                Err(e) => return Err(e.into()),
            };
            let public=key.rsa()?;
            // Owner-approved security fix 2026-11-05 (#523): never sign with a
            // factorable modulus or a tiny exponent; fail closed, never rotate silently.
            let small_e=*public.e()<*openssl::bn::BigNum::from_u32(65537)?;
            if (key.bits()<2048||small_e)&&!crate::mutants::on("oidc-weak-keys"){
                return Err(format!("OIDC signing key {private_path} is RSA-{} with public exponent {}: below the 2048-bit / e>=65537 minimum, refusing to sign. Rotate it: stop the auth server, delete {private_path} and {public_path}, restart to generate a fresh 2048-bit key, and have relying parties refetch /keys",key.bits(),public.e().to_dec_str()?).into());
            }
            let spki=key.public_key_to_der()?;
            fs::write(public_path, pem("PUBLIC KEY", &spki))?;
            fs::set_permissions(public_path, fs::Permissions::from_mode(0o644))?;
            let pair=match ring::signature::RsaKeyPair::from_pkcs8(&der){Ok(pair)=>Signer::Ring(pair),Err(_)=>Signer::Legacy(key)};
            Ok(Self {
                pair,
                n: public.n().to_vec(),
                e: public.e().to_vec(),
                kid: URL_SAFE_NO_PAD.encode(Sha256::digest(&spki)),
            })
        };
        work().map_err(|e| format!("OIDC key init failed: {e}"))
    }
    pub fn jwks(&self) -> String {
        let key = crate::issuance::object(&[
            ("use", json!("sig")),
            ("kty", json!("RSA")),
            ("kid", json!(self.kid)),
            ("alg", json!("RS256")),
            ("n", json!(URL_SAFE_NO_PAD.encode(&self.n))),
            ("e", json!(URL_SAFE_NO_PAD.encode(&self.e))),
        ]);
        format!("{{\"keys\":[{key}]}}\n")
    }
    pub fn sign(&self, claims: &Value) -> Result<String, String> {
        let header = json!({"alg":"RS256","kid":self.kid,"typ":"JWT"}).to_string();
        let payload = claims.to_string();
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(payload)
        );
        let sig=match &self.pair{
            Signer::Ring(pair)=>{let mut sig=vec![0;pair.public().modulus_len()];pair.sign(&ring::signature::RSA_PKCS1_SHA256,&ring::rand::SystemRandom::new(),input.as_bytes(),&mut sig).map_err(|_|"RS256 signing failed")?;sig},
            Signer::Legacy(key)=>{if key.bits()<1024{return Err("RS256 signing failed".into());}let sign=||->Result<Vec<u8>,openssl::error::ErrorStack>{let mut signer=openssl::sign::Signer::new(MessageDigest::sha256(),key)?;signer.set_rsa_padding(Padding::PKCS1)?;signer.sign_oneshot_to_vec(input.as_bytes())};sign().map_err(|_|"RS256 signing failed")?},
        };
        Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig)))
    }
    /// Only the configured OP key/RS256 profile is accepted; caller checks the
    /// token kind's issuer, lifetime, audience and durable capability binding.
    pub fn verify(&self, token: &str) -> Option<Value> {
        let mut parts = token.split('.');
        let (h, p, s) = (parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some() {
            return None;
        }
        let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(h).ok()?).ok()?;
        if header["alg"] != "RS256" || header["kid"] != self.kid {
            return None;
        }
        let input=format!("{h}.{p}");let signature=URL_SAFE_NO_PAD.decode(s).ok()?;
        match &self.pair{
            Signer::Ring(_)=>ring::signature::RsaPublicKeyComponents{n:&self.n,e:&self.e}.verify(&ring::signature::RSA_PKCS1_2048_8192_SHA256,input.as_bytes(),&signature).ok()?,
            Signer::Legacy(key)=>{if key.bits()<1024{return None;}let mut verifier=openssl::sign::Verifier::new(MessageDigest::sha256(),key).ok()?;verifier.set_rsa_padding(Padding::PKCS1).ok()?;if !verifier.verify_oneshot(&signature,input.as_bytes()).ok()?{return None;}},
        }
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p).ok()?).ok()
    }
}
fn parse_private(der:&[u8])->Result<PKey<Private>,Box<dyn std::error::Error>>{
    let key=PKey::private_key_from_pkcs8(der)?;if key.id()!=Id::RSA{return Err("OIDC private key is not RSA".into());}if !key.rsa()?.check_key()?{return Err("invalid OIDC RSA private key".into());}Ok(key)
}
fn decode_pem(pem: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let start = pem.find("-----BEGIN ").ok_or("PEM block is missing")?;
    let first = pem[start..].find('\n').ok_or("invalid PEM")? + start;
    let end = pem[first..].find("-----END ").ok_or("invalid PEM")? + first;
    Ok(STANDARD.decode(
        pem[first..end]
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect::<String>(),
    )?)
}
fn pem(label: &str, bytes: &[u8]) -> String {
    let raw = STANDARD.encode(bytes);
    let lines = raw
        .as_bytes()
        .chunks(64)
        .map(|s| std::str::from_utf8(s).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN {label}-----\n{lines}\n-----END {label}-----\n")
}
