//! Audited SSH transport. RSA private operations stay in OpenSSL, never RustCrypto RSA.
use super::{Config, Run};
use openssl::{
    bn::BigNum,
    hash::MessageDigest,
    pkey::{Id, PKey, Private},
    rsa::{Padding, RsaPrivateKeyBuilder},
};
use russh::{
    client,
    keys::{PrivateKey, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate},
    ChannelMsg, Disconnect,
};
use ssh_encoding::Encode;
use ssh_key::{Algorithm, HashAlg};
use std::sync::{atomic::Ordering, Arc};
pub(super) fn pinned(raw: &str) -> Option<PublicKeyOrCertificate> {
    if let Ok(certificate) = ssh_key::Certificate::from_openssh(raw) {
        return Some(PublicKeyOrCertificate::Certificate(certificate));
    }
    ssh_key::authorized_keys::AuthorizedKeys::new(raw)
        .next()
        .and_then(Result::ok)
        .map(|entry| entry.public_key().clone().into())
}
struct Pinned(PublicKeyOrCertificate);
impl client::Handler for Pinned {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(match (&self.0, key) {
            (
                PublicKeyOrCertificate::PublicKey { key: expected, .. },
                PublicKeyOrCertificate::PublicKey { key: actual, .. },
            ) => expected.key_data() == actual.key_data(),
            (
                PublicKeyOrCertificate::Certificate(expected),
                PublicKeyOrCertificate::Certificate(actual),
            ) => match (expected.to_bytes(), actual.to_bytes()) {
                (Ok(expected), Ok(actual)) => expected == actual,
                _ => false,
            },
            _ => false,
        })
    }
}
/// Per-stream bound on remote output kept in memory (#542, owner-approved security fix
/// 2026-11-05). Only the first 4096 bytes of the combined output are ever reported, so any
/// bound above that changes no visible byte; the rest is read and discarded so the command's
/// exit status still arrives.
pub(super) const OUTPUT_CAP: usize = 256 << 10;
#[derive(Default)]
pub(super) struct Capture(pub(super) Vec<u8>);
impl Capture {
    pub(super) fn push(&mut self, data: &[u8]) {
        // Test-only bug restoration (deploy-ssh-output-unbounded).
        let cap = if setjoin_contracts::mutants::on("deploy-ssh-output-unbounded") {
            usize::MAX
        } else {
            OUTPUT_CAP
        };
        let room = cap.saturating_sub(self.0.len());
        self.0.extend_from_slice(&data[..data.len().min(room)]);
    }
}
enum Key {
    Native(Arc<PrivateKey>),
    Rsa(PKey<Private>, PublicKey),
}
fn key(raw: &str) -> Result<Key, String> {
    if raw.contains("ENCRYPTED") {
        return Err("ssh: this private key is passphrase protected".into());
    }
    if let Ok(private) = PKey::private_key_from_pem(raw.as_bytes()) {
        if private.id() == Id::RSA {
            let rsa = private.rsa().map_err(|e| e.to_string())?;
            let public = ssh_key::public::RsaPublicKey::new(
                ssh_key::Mpint::from_positive_bytes(&rsa.e().to_vec()),
                ssh_key::Mpint::from_positive_bytes(&rsa.n().to_vec()),
            )
            .map_err(|e| e.to_string())?;
            return Ok(Key::Rsa(
                private,
                PublicKey::new(ssh_key::public::KeyData::Rsa(public), ""),
            ));
        }
    }
    let private =
        russh::keys::decode_secret_key(raw, None).map_err(|_| "ssh: no key found".to_owned())?;
    if let Some(key) = private.key_data().rsa() {
        let bn = |n: &ssh_key::Mpint| {
            BigNum::from_slice(n.as_positive_bytes().unwrap_or(&[])).map_err(|e| e.to_string())
        };
        let rsa = RsaPrivateKeyBuilder::new(
            bn(key.public().n())?,
            bn(key.public().e())?,
            bn(key.private().d())?,
        )
        .map_err(|e| e.to_string())?
        .set_factors(bn(key.private().p())?, bn(key.private().q())?)
        .map_err(|e| e.to_string())?
        .build();
        return Ok(Key::Rsa(
            PKey::from_rsa(rsa).map_err(|e| e.to_string())?,
            private.public_key().clone(),
        ));
    }
    Ok(Key::Native(Arc::new(private)))
}
#[derive(Debug)]
struct SignError(String);
impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for SignError {}
impl From<russh::SendError> for SignError {
    fn from(e: russh::SendError) -> Self {
        Self(e.to_string())
    }
}
struct RsaSigner(PKey<Private>);
impl russh::Signer for RsaSigner {
    type Error = SignError;
    async fn auth_sign(
        &mut self,
        _: &russh::keys::agent::AgentIdentity,
        hash: Option<HashAlg>,
        mut data: Vec<u8>,
    ) -> Result<Vec<u8>, SignError> {
        let result = (|| {
            let digest = match hash {
                Some(HashAlg::Sha512) => MessageDigest::sha512(),
                Some(HashAlg::Sha256) => MessageDigest::sha256(),
                _ => MessageDigest::sha1(),
            };
            let mut signer =
                openssl::sign::Signer::new(digest, &self.0).map_err(|e| e.to_string())?;
            signer
                .set_rsa_padding(Padding::PKCS1)
                .map_err(|e| e.to_string())?;
            let signature = signer
                .sign_oneshot_to_vec(&data)
                .map_err(|e| e.to_string())?;
            let signature = ssh_key::Signature::new(Algorithm::Rsa { hash }, signature)
                .map_err(|e| e.to_string())?;
            let mut wire = vec![];
            signature.encode(&mut wire).map_err(|e| e.to_string())?;
            wire.as_slice()
                .encode(&mut data)
                .map_err(|e| e.to_string())?;
            Ok::<_, String>(data)
        })();
        result.map_err(SignError)
    }
}
pub(super) async fn call(
    host: &str,
    user: &str,
    path: &str,
    command: &str,
    config: &Config,
    run: &Run,
) -> Result<Vec<u8>, (String, Vec<u8>)> {
    if run.cancel.is_cancelled() {
        return Err((
            format!("deployment cancelled before {host}: context canceled"),
            Vec::new(),
        ));
    }
    // #542 (owner-approved security fix 2026-11-05): only inline key material is accepted.
    // Frozen Go read an arbitrary local file named by the request; a path now yields the same
    // "no key found" failure a missing file always did, and the gateway reads nothing.
    let raw = if super::inline(path) {
        path.to_owned()
    } else if setjoin_contracts::mutants::on("deploy-ssh-key-path") {
        String::from_utf8_lossy(&std::fs::read(path).unwrap_or_default()).into_owned()
    } else {
        String::new()
    };
    let key = key(&raw).map_err(|e| (format!("parse key: {e}"), Vec::new()))?;
    let pin = pinned(&config.host_key).ok_or_else(|| {
        (
            "no DEPLOY_HOST_KEY configured — refusing to connect without SSH host key".into(),
            Vec::new(),
        )
    })?;
    let addr = if host.contains(':') {
        host.to_owned()
    } else {
        format!("{host}:22")
    };
    let connecting = async {
        let mut client_config = client::Config::default();
        // Go offers certificate algorithms before bare keys. The callback still
        // requires the exact configured public key or certificate bytes.
        client_config.preferred.host_key_certificates = client_config.preferred.key.clone();
        let mut session = client::connect(Arc::new(client_config), addr, Pinned(pin))
            .await
            .map_err(|e| e.to_string())?;
        let auth = match key {
            Key::Native(key) => session
                .authenticate_publickey(user, PrivateKeyWithHashAlg::new(key, None))
                .await
                .map_err(|e| e.to_string())?,
            Key::Rsa(key, public) => {
                let hash = session
                    .best_supported_rsa_hash()
                    .await
                    .map_err(|e| e.to_string())?
                    .flatten();
                session
                    .authenticate_publickey_with(user, public, hash, &mut RsaSigner(key))
                    .await
                    .map_err(|e| e.to_string())?
            }
        };
        if !auth.success() {
            return Err("ssh: handshake failed: ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain".into());
        }
        Ok::<_, String>(session)
    };
    let session = tokio::select! {_ = run.cancel.cancelled()=>return Err((format!("dial {host}: context canceled"),Vec::new())),r=tokio::time::timeout(std::time::Duration::from_secs(10),connecting)=>r.map_err(|_|(format!("dial {host}: i/o timeout"),Vec::new()))?.map_err(|e|(format!("dial {host}: {e}"),Vec::new()))?};
    let mut channel = tokio::select! {_ = run.cancel.cancelled()=>{let _=session.disconnect(Disconnect::ByApplication,"","").await;return Err((format!("deployment cancelled before {host}: context canceled"),Vec::new()));},r=tokio::time::timeout(std::time::Duration::from_secs(10),session.channel_open_session())=>r.map_err(|_|(format!("open session {host}: timeout"),Vec::new()))?.map_err(|e|(e.to_string(),Vec::new()))?};
    tokio::select! {
        _=run.cancel.cancelled()=>{
            let _=session.disconnect(Disconnect::ByApplication,"","").await;
            run.unknown.store(true,Ordering::Release);
            return Err((format!("deployment cancelled during {host} with unconfirmed remote termination (wait: remote command exited without exit status or exit signal): context canceled"),Vec::new()));
        },
        result=channel.exec(true,command)=>result.map_err(|e|(e.to_string(),Vec::new()))?,
    }
    let collect = async {
        let (mut out, mut err, mut status, mut signal) = (Capture::default(), Capture::default(), None, None);
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Data { data } => out.push(&data),
                ChannelMsg::ExtendedData { data, .. } => err.push(&data),
                ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                ChannelMsg::ExitSignal {
                    signal_name,
                    error_message,
                    ..
                } => {
                    signal = Some((
                        match signal_name {
                            russh::Sig::Custom(name) => name,
                            name => format!("{name:?}"),
                        },
                        error_message,
                    ))
                }
                _ => {}
            }
        }
        let mut output = out.0;
        if !err.0.is_empty() {
            output.extend_from_slice(b"\n[stderr]\n");
            output.extend(err.0);
        }
        (output, status, signal)
    };
    tokio::pin!(collect);
    let result = tokio::select! {r=&mut collect=>Some(r),_=run.cancel.cancelled()=>{let _=session.disconnect(Disconnect::ByApplication,"","").await;match tokio::time::timeout(std::time::Duration::from_secs(5),&mut collect).await{Ok((output,status,signal))=>{if status.is_none()&&signal.is_none(){run.unknown.store(true,Ordering::Release);return Err((format!("deployment cancelled during {host} with unconfirmed remote termination (wait: remote command exited without exit status or exit signal): context canceled"),output));}return Err((format!("deployment cancelled during {host}: context canceled"),output));},Err(_)=>{run.unknown.store(true,Ordering::Release);return Err((format!("deployment cancelled during {host} with unconfirmed remote termination: context canceled"),Vec::new()));}}}};
    let _ = session.disconnect(Disconnect::ByApplication, "", "").await;
    let (output, status, signal) = result.unwrap();
    // x/crypto/ssh Waitmsg: an explicit zero wins; otherwise synthesize
    // 128+signal only when the peer omitted exit-status, then retain its message.
    if status == Some(0) {
        return Ok(output);
    }
    if status.is_none() && signal.is_none() {
        return Err((
            "wait: remote command exited without exit status or exit signal".into(),
            output,
        ));
    }
    let code = status.unwrap_or_else(|| {
        128 + match signal.as_ref().map(|(name, _)| name.as_str()) {
            Some("ABRT") => 6,
            Some("ALRM") => 14,
            Some("FPE") => 8,
            Some("HUP") => 1,
            Some("ILL") => 4,
            Some("INT") => 2,
            Some("KILL") => 9,
            Some("PIPE") => 13,
            Some("QUIT") => 3,
            Some("SEGV") => 11,
            Some("TERM") => 15,
            _ => 0,
        }
    });
    let mut error = format!("Process exited with status {code}");
    if let Some((name, message)) = signal {
        if !name.is_empty() {
            error.push_str(&format!(" from signal {name}"));
        }
        if !message.is_empty() {
            error.push_str(&format!(". Reason was: {message}"));
        }
    }
    Err((error, output))
}

#[cfg(test)]
mod secfix11_tests {
    use super::*;
    /// #542: remote output is bounded while it is read, not only when it is reported.
    #[test]
    fn remote_output_is_capped_while_reading() {
        let mut capture = Capture::default();
        let chunk = vec![b'x'; 64 << 10];
        for _ in 0..64 {
            capture.push(&chunk);
        }
        assert_eq!(capture.0.len(), OUTPUT_CAP);
        assert!(OUTPUT_CAP > 4096, "the reported 4096-byte prefix is untouched");
    }
}
