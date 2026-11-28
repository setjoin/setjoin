//! End-to-end DB + real libgssapi integration coverage for #355b native
//! Kerberos/SPNEGO (`Authorization: Negotiate`) on CalDAV, CardDAV, and Drive
//! `/api/drive/native-token`.
use crate::common;

use aes::{
    cipher::{BlockEncrypt, KeyInit},
    Aes128,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Utc};
use common::BoxError;
use futures_util::FutureExt;
use hmac::{Hmac, Mac};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_authz::{
    auth_chain::Chain,
    kerberos::{GssapiVerifier, KerberosConfig, KerberosValidator},
};
use setjoin_config_secret::CryptoProfile;
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::{
    caldav::CalDavRoute,
    carddav::CardDavRoute,
    dav_auth::DavBasicAuth,
    drive_native::NativeTokenRoute,
    runtime_access::{RuntimeAccess, RuntimeGate},
    Config, Gateway, RouteTable, TrustedProxies,
};
use setjoin_pg::{workers::WorkerDatabase, ScopedExecutor};
use setjoin_threat::{
    Config as ThreatConfig, ConnectionMeta, Gate as ThreatGateImpl, ThreatAction, ThreatGate,
    WorkerPools,
};
use sha1::Sha1;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const RUNTIME_FLAGS: [&str; 5] = [
    "feature.cae_runtime",
    "feature.conditional_access",
    "feature.device_trust_enforcement",
    "feature.device_lockdown",
    "feature.token_binding",
];

// ---------------------------------------------------------------------------
// Real RFC 3962 + RFC 4120 + RFC 4178 SPNEGO/AP-REQ + MIT v0x0502 keytab minter
// ---------------------------------------------------------------------------

fn gcd(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}
fn lcm(a: usize, b: usize) -> usize {
    a / gcd(a, b) * b
}
fn rot_right_13(input: &[u8], n: usize) -> Vec<u8> {
    let bit_len = input.len() * 8;
    let shift = (13 * n) % bit_len;
    let mut out = vec![0u8; input.len()];
    for bit in 0..bit_len {
        let src_bit = (bit + bit_len - shift) % bit_len;
        let val = (input[src_bit / 8] >> (7 - (src_bit % 8))) & 1;
        out[bit / 8] |= val << (7 - (bit % 8));
    }
    out
}
fn ones_complement_add(a: &mut [u8], b: &[u8]) {
    let mut carry = 0u16;
    for i in (0..a.len()).rev() {
        let sum = a[i] as u16 + b[i] as u16 + carry;
        a[i] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    while carry != 0 {
        for i in (0..a.len()).rev() {
            let sum = a[i] as u16 + carry;
            a[i] = (sum & 0xff) as u8;
            carry = sum >> 8;
            if carry == 0 {
                break;
            }
        }
    }
}
fn n_fold(input: &[u8], out_bytes: usize) -> Vec<u8> {
    let total = lcm(out_bytes, input.len());
    let copies = total / input.len();
    let mut expanded = Vec::with_capacity(total);
    for i in 0..copies {
        expanded.extend_from_slice(&rot_right_13(input, i));
    }
    let mut acc = vec![0u8; out_bytes];
    for chunk in expanded.chunks_exact(out_bytes) {
        ones_complement_add(&mut acc, chunk);
    }
    acc
}
fn dk_aes128(base_key: &[u8; 16], usage: u32, suffix: u8) -> [u8; 16] {
    let mut constant = [0u8; 5];
    constant[..4].copy_from_slice(&usage.to_be_bytes());
    constant[4] = suffix;
    let folded = n_fold(&constant, 16);
    let cipher = Aes128::new_from_slice(base_key).unwrap();
    let mut block = aes::Block::from(<[u8; 16]>::try_from(folded.as_slice()).unwrap());
    cipher.encrypt_block(&mut block);
    let mut out = [0u8; 16];
    out.copy_from_slice(&block);
    out
}
fn encrypt_aes128_cts_hmac_sha1_96(
    base_key: &[u8; 16],
    usage: u32,
    confounder: [u8; 16],
    plaintext: &[u8],
) -> Vec<u8> {
    let ke = dk_aes128(base_key, usage, 0xaa);
    let ki = dk_aes128(base_key, usage, 0x55);
    let mut plain = Vec::with_capacity(16 + plaintext.len());
    plain.extend_from_slice(&confounder);
    plain.extend_from_slice(plaintext);
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(&ki).unwrap();
    mac.update(&plain);
    let hmac_full = mac.finalize().into_bytes();
    let cipher = Aes128::new_from_slice(&ke).unwrap();
    let n = plain.len();
    let mut ct = Vec::with_capacity(n + 12);
    if n == 16 {
        let mut b = aes::Block::from(<[u8; 16]>::try_from(plain.as_slice()).unwrap());
        cipher.encrypt_block(&mut b);
        ct.extend_from_slice(&b);
    } else {
        let rem = n % 16;
        let num_blocks = n.div_ceil(16);
        let mut prev = [0u8; 16];
        let mut blocks: Vec<[u8; 16]> = Vec::with_capacity(num_blocks);
        for i in 0..num_blocks {
            let start = i * 16;
            let end = (start + 16).min(n);
            let mut cur = [0u8; 16];
            cur[..(end - start)].copy_from_slice(&plain[start..end]);
            for j in 0..16 {
                cur[j] ^= prev[j];
            }
            let mut b = aes::Block::from(cur);
            cipher.encrypt_block(&mut b);
            let mut enc = [0u8; 16];
            enc.copy_from_slice(&b);
            prev = enc;
            blocks.push(enc);
        }
        for b in &blocks[..num_blocks - 2] {
            ct.extend_from_slice(b);
        }
        ct.extend_from_slice(&blocks[num_blocks - 1]);
        let tail_len = if rem == 0 { 16 } else { rem };
        ct.extend_from_slice(&blocks[num_blocks - 2][..tail_len]);
    }
    ct.extend_from_slice(&hmac_full[..12]);
    ct
}
fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xff {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    }
}
fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(tag);
    out.extend_from_slice(&der_len(body.len()));
    out.extend_from_slice(body);
    out
}
fn der_ctx(num: u8, inner: &[u8]) -> Vec<u8> {
    der_tlv(0xa0 | num, inner)
}
fn der_int(val: i64) -> Vec<u8> {
    let bytes = val.to_be_bytes();
    let mut start = 0;
    while start < 7 && bytes[start] == 0 {
        start += 1;
    }
    let mut body = Vec::new();
    if bytes[start] & 0x80 != 0 {
        body.push(0);
    }
    body.extend_from_slice(&bytes[start..]);
    der_tlv(0x02, &body)
}
fn der_general_string(s: &str) -> Vec<u8> {
    der_tlv(0x1b, s.as_bytes())
}
fn der_generalized_time(ts: DateTime<Utc>) -> Vec<u8> {
    der_tlv(0x18, ts.format("%Y%m%d%H%M%SZ").to_string().as_bytes())
}
fn der_principal(name_type: i64, components: &[&str]) -> Vec<u8> {
    let mut strs = Vec::new();
    for c in components {
        strs.extend_from_slice(&der_general_string(c));
    }
    let mut seq = Vec::new();
    seq.extend_from_slice(&der_ctx(0, &der_int(name_type)));
    seq.extend_from_slice(&der_ctx(1, &der_tlv(0x30, &strs)));
    der_tlv(0x30, &seq)
}
fn der_encryption_key(enctype: i64, key: &[u8]) -> Vec<u8> {
    let mut seq = Vec::new();
    seq.extend_from_slice(&der_ctx(0, &der_int(enctype)));
    seq.extend_from_slice(&der_ctx(1, &der_tlv(0x04, key)));
    der_tlv(0x30, &seq)
}
fn der_encrypted_data(enctype: i64, kvno: Option<i64>, cipher: &[u8]) -> Vec<u8> {
    let mut seq = Vec::new();
    seq.extend_from_slice(&der_ctx(0, &der_int(enctype)));
    if let Some(v) = kvno {
        seq.extend_from_slice(&der_ctx(1, &der_int(v)));
    }
    seq.extend_from_slice(&der_ctx(2, &der_tlv(0x04, cipher)));
    der_tlv(0x30, &seq)
}
fn build_mit_keytab(realm: &str, components: &[&str], kvno: u8, key: &[u8; 16]) -> Vec<u8> {
    let mut entry = Vec::new();
    entry.extend_from_slice(&(components.len() as u16).to_be_bytes());
    entry.extend_from_slice(&(realm.len() as u16).to_be_bytes());
    entry.extend_from_slice(realm.as_bytes());
    for c in components {
        entry.extend_from_slice(&(c.len() as u16).to_be_bytes());
        entry.extend_from_slice(c.as_bytes());
    }
    entry.extend_from_slice(&1u32.to_be_bytes());
    entry.extend_from_slice(&0u32.to_be_bytes());
    entry.push(kvno);
    entry.extend_from_slice(&17u16.to_be_bytes());
    entry.extend_from_slice(&(key.len() as u16).to_be_bytes());
    entry.extend_from_slice(key);
    entry.extend_from_slice(&(kvno as u32).to_be_bytes());
    let mut kt = vec![0x05, 0x02];
    kt.extend_from_slice(&(entry.len() as i32).to_be_bytes());
    kt.extend_from_slice(&entry);
    kt
}

struct TicketMinter {
    service_key: [u8; 16],
    realm: String,
    cusec: AtomicUsize,
}
impl TicketMinter {
    fn negotiate_header(&self, client: &str, client_realm: &str) -> String {
        const SPNEGO_OID: [u8; 6] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
        const KRB5_OID: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];
        let seq_n = self.cusec.fetch_add(1, Ordering::SeqCst) as i64 + 100;
        let now = Utc::now();
        let end = now + chrono::Duration::hours(1);
        let session_key = [0x55u8; 16];
        let seed = (seq_n & 0xff) as u8;

        let mut enc_tkt = Vec::new();
        enc_tkt.extend_from_slice(&der_ctx(0, &der_tlv(0x03, &[0, 0, 0, 0, 0])));
        enc_tkt.extend_from_slice(&der_ctx(1, &der_encryption_key(17, &session_key)));
        enc_tkt.extend_from_slice(&der_ctx(2, &der_general_string(client_realm)));
        enc_tkt.extend_from_slice(&der_ctx(3, &der_principal(1, &[client])));
        let mut transited = Vec::new();
        transited.extend_from_slice(&der_ctx(0, &der_int(1)));
        transited.extend_from_slice(&der_ctx(1, &der_tlv(0x04, &[])));
        enc_tkt.extend_from_slice(&der_ctx(4, &der_tlv(0x30, &transited)));
        enc_tkt.extend_from_slice(&der_ctx(5, &der_generalized_time(now)));
        enc_tkt.extend_from_slice(&der_ctx(7, &der_generalized_time(end)));
        let enc_tkt_der = der_tlv(0x63, &der_tlv(0x30, &enc_tkt));
        let tkt_cipher =
            encrypt_aes128_cts_hmac_sha1_96(&self.service_key, 2, [seed; 16], &enc_tkt_der);

        let mut tkt = Vec::new();
        tkt.extend_from_slice(&der_ctx(0, &der_int(5)));
        tkt.extend_from_slice(&der_ctx(1, &der_general_string(&self.realm)));
        tkt.extend_from_slice(&der_ctx(
            2,
            &der_principal(2, &["HTTP", "mail.example.test"]),
        ));
        tkt.extend_from_slice(&der_ctx(3, &der_encrypted_data(17, Some(1), &tkt_cipher)));
        let ticket_der = der_tlv(0x61, &der_tlv(0x30, &tkt));

        let mut cksum_body = vec![0u8; 24];
        cksum_body[0..4].copy_from_slice(&16u32.to_le_bytes());
        let mut cksum = Vec::new();
        cksum.extend_from_slice(&der_ctx(0, &der_int(0x8003)));
        cksum.extend_from_slice(&der_ctx(1, &der_tlv(0x04, &cksum_body)));

        let mut auth = Vec::new();
        auth.extend_from_slice(&der_ctx(0, &der_int(5)));
        auth.extend_from_slice(&der_ctx(1, &der_general_string(client_realm)));
        auth.extend_from_slice(&der_ctx(2, &der_principal(1, &[client])));
        auth.extend_from_slice(&der_ctx(3, &der_tlv(0x30, &cksum)));
        auth.extend_from_slice(&der_ctx(4, &der_int(seq_n)));
        auth.extend_from_slice(&der_ctx(5, &der_generalized_time(now)));
        let auth_der = der_tlv(0x62, &der_tlv(0x30, &auth));
        let auth_cipher = encrypt_aes128_cts_hmac_sha1_96(
            &session_key,
            11,
            [seed.wrapping_add(1); 16],
            &auth_der,
        );

        let mut ap_req = Vec::new();
        ap_req.extend_from_slice(&der_ctx(0, &der_int(5)));
        ap_req.extend_from_slice(&der_ctx(1, &der_int(14)));
        ap_req.extend_from_slice(&der_ctx(2, &der_tlv(0x03, &[0, 0, 0, 0, 0])));
        ap_req.extend_from_slice(&der_ctx(3, &ticket_der));
        ap_req.extend_from_slice(&der_ctx(4, &der_encrypted_data(17, None, &auth_cipher)));
        let ap_req_der = der_tlv(0x6e, &der_tlv(0x30, &ap_req));

        let mut inner = Vec::new();
        inner.extend_from_slice(&der_tlv(0x06, &KRB5_OID));
        inner.extend_from_slice(&[0x01, 0x00]);
        inner.extend_from_slice(&ap_req_der);
        let gss_krb5 = der_tlv(0x60, &inner);

        let mech_types = der_tlv(0x30, &der_tlv(0x06, &KRB5_OID));
        let mut neg_seq = Vec::new();
        neg_seq.extend_from_slice(&der_ctx(0, &mech_types));
        neg_seq.extend_from_slice(&der_ctx(2, &der_tlv(0x04, &gss_krb5)));
        let mut spnego_body = Vec::new();
        spnego_body.extend_from_slice(&der_tlv(0x06, &SPNEGO_OID));
        spnego_body.extend_from_slice(&der_ctx(0, &der_tlv(0x30, &neg_seq)));
        format!("Negotiate {}", STANDARD.encode(der_tlv(0x60, &spnego_body)))
    }
}

struct RunningServer {
    addr: SocketAddr,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}
impl RunningServer {
    async fn close(mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        let _ = (&mut self.task).await;
    }
}
impl Drop for RunningServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Clone)]
struct RecordingThreat {
    intercepts: Arc<Mutex<Vec<ConnectionMeta>>>,
    records: Arc<Mutex<Vec<(ConnectionMeta, bool, i64)>>>,
    ip_failures: Arc<Mutex<Vec<ConnectionMeta>>>,
    lockout_checks: Arc<Mutex<Vec<ConnectionMeta>>>,
    account_lockout: Arc<Mutex<(ThreatAction, Duration)>>,
}
impl RecordingThreat {
    fn new() -> Self {
        Self {
            intercepts: Arc::new(Mutex::new(Vec::new())),
            records: Arc::new(Mutex::new(Vec::new())),
            ip_failures: Arc::new(Mutex::new(Vec::new())),
            lockout_checks: Arc::new(Mutex::new(Vec::new())),
            account_lockout: Arc::new(Mutex::new((ThreatAction::Allow, Duration::ZERO))),
        }
    }
}
impl ThreatGate for RecordingThreat {
    fn intercept<'a>(
        &'a self,
        meta: &'a ConnectionMeta,
    ) -> futures_util::future::BoxFuture<'a, (ThreatAction, Duration)> {
        Box::pin(async move {
            self.intercepts.lock().unwrap().push(meta.clone());
            (ThreatAction::Allow, Duration::ZERO)
        })
    }
    fn record_result<'a>(
        &'a self,
        meta: &'a ConnectionMeta,
        success: bool,
        user_id: i64,
    ) -> futures_util::future::BoxFuture<'a, ()> {
        Box::pin(async move {
            self.records
                .lock()
                .unwrap()
                .push((meta.clone(), success, user_id));
        })
    }
    fn evaluate_post_auth<'a>(
        &'a self,
        _meta: &'a mut ConnectionMeta,
    ) -> futures_util::future::BoxFuture<'a, (ThreatAction, String)> {
        Box::pin(async move { (ThreatAction::Allow, String::new()) })
    }
    fn check_account_lockout<'a>(
        &'a self,
        meta: &'a ConnectionMeta,
    ) -> futures_util::future::BoxFuture<'a, (ThreatAction, Duration)> {
        Box::pin(async move {
            self.lockout_checks.lock().unwrap().push(meta.clone());
            *self.account_lockout.lock().unwrap()
        })
    }
    fn record_ip_failure<'a>(
        &'a self,
        meta: &'a ConnectionMeta,
    ) -> futures_util::future::BoxFuture<'a, ()> {
        Box::pin(async move {
            self.ip_failures.lock().unwrap().push(meta.clone());
        })
    }
}

async fn set_runtime_flags(
    owner: &tokio_postgres::Client,
    enabled: &[&str],
) -> Result<(), BoxError> {
    for key in RUNTIME_FLAGS {
        let on = enabled.contains(&key);
        owner
            .execute(
                "INSERT INTO feature_toggles(key,enabled) VALUES($1,$2) \
                 ON CONFLICT(key) DO UPDATE SET enabled=$2",
                &[&key, &on],
            )
            .await?;
    }
    Ok(())
}

async fn send_req(
    addr: SocketAddr,
    method: &str,
    uri: &str,
    auth: Option<&str>,
    cookie: Option<&str>,
    body: &[u8],
) -> Result<(u16, Option<String>, Vec<u8>), BoxError> {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "mail.example.test")
        .header("origin", "http://mail.example.test")
        .header("x-requested-with", "XMLHttpRequest");
    if let Some(a) = auth {
        b = b.header("authorization", a);
    }
    if let Some(c) = cookie {
        b = b.header("cookie", c);
    }
    let req = b.body(common::full(body.to_vec()))?;
    let resp = common::send(addr, req).await;
    let status = resp.status().as_u16();
    let www = resp
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let bytes = common::body_bytes(resp).await.to_vec();
    Ok((status, www, bytes))
}

#[allow(clippy::too_many_arguments)]
async fn spawn_dav_gateway(
    db: &Db,
    exec: &ScopedExecutor,
    keys: Arc<setjoin_authz::jwks::Jwks>,
    chain: Option<Arc<Chain>>,
    threat: Arc<dyn ThreatGate>,
    kerberos: Option<Arc<dyn KerberosValidator>>,
    drive_secret: &str,
    go_upstream: Option<SocketAddr>,
) -> Result<RunningServer, BoxError> {
    let worker_exec = ScopedExecutor::from_dsn(&db.dsn, 4).map_err(|e| e.0)?;
    let worker_db = WorkerDatabase::new(&db.dsn)?;
    let runtime = Arc::new(
        RuntimeAccess::new(exec.clone(), keys.clone(), "mailserver".into())
            .with_workers(worker_exec, worker_db)
            .with_direct(db.direct.clone())
            .with_device_secret(drive_secret.as_bytes().to_vec(), CryptoProfile::Standard),
    );
    runtime.initialize().await;

    let basic = DavBasicAuth {
        chain,
        password_cache: Arc::new(setjoin_authz::basic::PasswordCache::new()),
        threat: Some(threat),
        runtime: Some(runtime.clone()),
        kerberos,
    };
    let caldav = CalDavRoute::new(exec.clone(), keys.clone(), "mailserver".into())
        .await
        .with_basic_auth(basic.clone());
    let carddav = CardDavRoute::new(exec.clone(), keys.clone(), "mailserver".into())
        .with_basic_auth(basic.clone());
    let drive = NativeTokenRoute::new(exec.clone(), keys, "mailserver".into(), Some(drive_secret))
        .with_basic_auth(basic);

    let routes = RouteTable::proxy_all()
        .with(caldav)
        .with(carddav)
        .with(drive)
        .with_runtime(runtime);
    let upstream = go_upstream
        .map(|a| format!("http://{a}").parse())
        .transpose()?;
    let gw = Gateway::new(
        Config {
            upstream,
            trusted_proxies: TrustedProxies::parse("")?,
            upstream_header_timeout: Duration::from_secs(5),
            edge_limit: None,
        },
        routes,
    )?;
    let listener = setjoin_conformance::ports::listener().await;
    let addr = listener.local_addr()?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let _ = gw
            .serve_until(listener, async move {
                let _ = rx.await;
            })
            .await;
    });
    Ok(RunningServer {
        addr,
        stop: Some(tx),
        task,
    })
}

fn member_jwt(user_id: i64, email: &str, secret: &str) -> String {
    let now = Utc::now().timestamp();
    let claims = json!({
        "uid": user_id,
        "email": email,
        "typ": "access",
        "jti": format!("neg-cookie-{user_id}"),
        "fam": "355b0000-0000-4000-8000-000000000001",
        "iss": "mailserver",
        "aud": ["mailserver-gateway"],
        "iat": now,
        "nbf": now,
        "exp": now + 3600,
        "amr": ["pwd"],
        "acr": "aal1",
    });
    setjoin_authz::legacy_jwt::sign_hs256(secret.as_bytes(), &claims.to_string())
}

#[tokio::test]
async fn dav_and_drive_negotiate_native_auth_threat_and_runtime_gates() -> Result<(), BoxError> {
    let _guard = SERIAL.lock().await;
    let Some(db) = Db::for_case("dav-negotiate-auth") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let exec =
        ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4).map_err(|e| e.0)?;

    // Save state we mutate
    let toggle_keys: Vec<String> = RUNTIME_FLAGS.iter().map(|s| (*s).to_owned()).collect();
    let saved_toggles: Vec<(String, bool)> = owner
        .query(
            "SELECT key, enabled FROM feature_toggles WHERE key = ANY($1)",
            &[&toggle_keys],
        )
        .await?
        .into_iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    let saved_krb_enabled: bool = owner
        .query_one(
            "SELECT enabled FROM auth_methods WHERE slug = 'kerberos'",
            &[],
        )
        .await?
        .get(0);

    let dir = tempfile::tempdir()?;
    let kt_path = dir.path().join("dav:test.keytab");
    let service_key = [0x42u8; 16];
    let realm = "EXAMPLE.TEST";
    std::fs::write(
        &kt_path,
        build_mit_keytab(realm, &["HTTP", "mail.example.test"], 1, &service_key),
    )?;
    let verifier = Arc::new(GssapiVerifier::new(KerberosConfig {
        keytab: kt_path.clone(),
        realm: realm.into(),
    })?);
    let minter = TicketMinter {
        service_key,
        realm: realm.into(),
        cusec: AtomicUsize::new(1),
    };

    let member = fixture::account(&owner, "neg-member").await?;
    let cookie_user = fixture::account(&owner, "neg-cookie").await?;
    let totp_user = fixture::account(&owner, "neg-totp").await?;
    let guest_user = fixture::account(&owner, "neg-guest").await?;
    let disabled_user = fixture::account(&owner, "neg-disabled").await?;

    let member_email: String = owner
        .query_one("SELECT email FROM users WHERE id=$1", &[&member.user])
        .await?
        .get(0);
    let cookie_email: String = owner
        .query_one("SELECT email FROM users WHERE id=$1", &[&cookie_user.user])
        .await?
        .get(0);
    let _totp_email: String = owner
        .query_one("SELECT email FROM users WHERE id=$1", &[&totp_user.user])
        .await?
        .get(0);
    let guest_email: String = owner
        .query_one("SELECT email FROM users WHERE id=$1", &[&guest_user.user])
        .await?
        .get(0);

    let member_principal = format!("neg-member-{}@{realm}", member.user);
    let totp_principal = format!("neg-totp-{}@{realm}", totp_user.user);
    let guest_principal = format!("neg-guest-{}@{realm}", guest_user.user);
    let disabled_principal = format!("neg-disabled-{}@{realm}", disabled_user.user);

    owner
        .execute(
            "UPDATE users SET krb5_principal=$1 WHERE id=$2",
            &[&member_principal, &member.user],
        )
        .await?;
    owner
        .execute(
            "UPDATE users SET krb5_principal=$1, totp_enabled=TRUE WHERE id=$2",
            &[&totp_principal, &totp_user.user],
        )
        .await?;
    owner
        .execute(
            "UPDATE users SET krb5_principal=$1 WHERE id=$2",
            &[&guest_principal, &guest_user.user],
        )
        .await?;
    owner
        .execute(
            "INSERT INTO guest_accounts(user_id, invited_email, invited_by_email, host_domain_id, status, expires_at) \
             VALUES($1, $2, 'inviter@example.test', $3, 'active', now() + interval '1 day')",
            &[&guest_user.user, &guest_email, &member.domain],
        )
        .await?;
    owner
        .execute(
            "UPDATE users SET krb5_principal=$1, enabled=FALSE WHERE id=$2",
            &[&disabled_principal, &disabled_user.user],
        )
        .await?;

    let drive_secret = "dav-negotiate-test-jwt-secret-0123456789";
    let keys = Arc::new(
        setjoin_authz::jwks::Jwks::with_fetch(Box::new(|| {
            Box::pin(async {
                Ok(include_bytes!("../../../tests/conformance/jmap/test-jwks.json").to_vec())
            })
        }))
        .with_legacy_keys(setjoin_authz::legacy_jwt::LegacyKeys::new(
            drive_secret.as_bytes(),
            &["authserver-hmac-1", "mailserver-drive-native-1"],
            None,
        )?),
    );

    let res = std::panic::AssertUnwindSafe(async {
        set_runtime_flags(&owner, &[]).await?;
        let go_hits = Arc::new(AtomicUsize::new(0));
        let hits_clone = go_hits.clone();
        let go_upstream = common::fake_upstream(move |_| {
            let hits = hits_clone.clone();
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                Response::builder()
                    .status(218)
                    .body(common::full("go-negotiate"))
                    .unwrap()
            }
        })
        .await;

        // 1. Chain fail-closed: `chain: None` with verifier present MUST return 401 (no Go hop)
        let threat_none = Arc::new(RecordingThreat::new());
        let srv_no_chain = spawn_dav_gateway(
            &db,
            &exec,
            keys.clone(),
            None,
            threat_none.clone(),
            Some(verifier.clone()),
            drive_secret,
            Some(go_upstream),
        )
        .await?;
        let tok = minter.negotiate_header(&format!("neg-member-{}", member.user), realm);
        let (st, www, _) = send_req(srv_no_chain.addr, "OPTIONS", "/caldav/", Some(&tok), None, b"").await?;
        assert_eq!(st, 401);
        assert_eq!(www.as_deref(), Some("Negotiate, Bearer realm=\"mailserver\""));
        assert!(threat_none.intercepts.lock().unwrap().is_empty());
        assert_eq!(go_hits.load(Ordering::SeqCst), 0);
        srv_no_chain.close().await;

        // 2. Chain::listen initial connect failure clears kerberos_allowed() to false
        let listen_chain = Arc::new(Chain::default());
        owner
            .execute("UPDATE auth_methods SET enabled=TRUE WHERE slug='kerberos'", &[])
            .await?;
        listen_chain.reload(&exec).await?;
        assert!(listen_chain.kerberos_allowed());
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let listen_task = tokio::spawn(listen_chain.clone().listen(
            exec.clone(),
            "postgres://127.0.0.1:1/nope".into(),
            stop_rx,
        ));
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !listen_chain.kerberos_allowed(),
            "initial LISTEN failure must clear kerberos_allowed()"
        );
        let _ = stop_tx.send(());
        let _ = listen_task.await;

        // 3. auth_methods enabled=FALSE -> 401 with zero side effects; enabled=TRUE -> 200 on all 3 routes
        owner
            .execute("UPDATE auth_methods SET enabled=FALSE WHERE slug='kerberos'", &[])
            .await?;
        let chain = Arc::new(Chain::default());
        chain.reload(&exec).await?;
        assert!(!chain.kerberos_allowed());

        let threat = Arc::new(RecordingThreat::new());
        let srv = spawn_dav_gateway(
            &db,
            &exec,
            keys.clone(),
            Some(chain.clone()),
            threat.clone(),
            Some(verifier.clone()),
            drive_secret,
            Some(go_upstream),
        )
        .await?;

        let tok_off = minter.negotiate_header(&format!("neg-member-{}", member.user), realm);
        let (st, www, _) = send_req(srv.addr, "OPTIONS", "/caldav/", Some(&tok_off), None, b"").await?;
        assert_eq!(st, 401);
        assert_eq!(www.as_deref(), Some("Negotiate, Bearer realm=\"mailserver\""));
        assert!(threat.intercepts.lock().unwrap().is_empty());

        // Enable Kerberos in auth_methods and reload chain
        owner
            .execute("UPDATE auth_methods SET enabled=TRUE WHERE slug='kerberos'", &[])
            .await?;
        chain.reload(&exec).await?;
        assert!(chain.kerberos_allowed());

        // Valid SPNEGO succeeds on CalDAV, CardDAV, and Drive native-token
        for (method, uri, body) in [
            ("OPTIONS", "/caldav/", b"".as_slice()),
            ("OPTIONS", "/carddav/", b"".as_slice()),
            ("POST", "/api/drive/native-token", b"{}".as_slice()),
        ] {
            let tok = minter.negotiate_header(&format!("neg-member-{}", member.user), realm);
            let (st, _, bytes) = send_req(srv.addr, method, uri, Some(&tok), None, body).await?;
            assert_eq!(st, 200, "valid SPNEGO on {method} {uri}");
            if uri == "/api/drive/native-token" {
                let v: Value = serde_json::from_slice(&bytes)?;
                assert!(v["token"].as_str().is_some_and(|s| !s.is_empty()));
            }
        }
        assert_eq!(go_hits.load(Ordering::SeqCst), 0);

        // 4. Cookie + Negotiate precedence across all 3 routes:
        //    (a) Valid Cookie (cookie_user) + invalid Negotiate -> succeeds as cookie_user
        //    (b) Invalid Cookie + valid Negotiate (member) -> falls through to Kerberos and succeeds
        let cookie_hdr = format!(
            "access_token={}",
            member_jwt(cookie_user.user, &cookie_email, drive_secret)
        );
        for (method, uri, body) in [
            ("OPTIONS", "/caldav/", b"".as_slice()),
            ("OPTIONS", "/carddav/", b"".as_slice()),
            ("POST", "/api/drive/native-token", b"{}".as_slice()),
        ] {
            let (st, _, bytes) = send_req(
                srv.addr,
                method,
                uri,
                Some("Negotiate YII="),
                Some(&cookie_hdr),
                body,
            )
            .await?;
            assert_eq!(st, 200, "valid cookie must outrank bad Negotiate on {method} {uri}");
            if uri == "/api/drive/native-token" {
                let v: Value = serde_json::from_slice(&bytes)?;
                let minted = v["token"].as_str().unwrap();
                let payload_b64 = minted.split('.').nth(1).unwrap();
                let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(payload_b64)?;
                let claims: Value = serde_json::from_slice(&payload)?;
                assert_eq!(claims["uid"], cookie_user.user);
            }

            let tok = minter.negotiate_header(&format!("neg-member-{}", member.user), realm);
            let (st, _, _) = send_req(
                srv.addr,
                method,
                uri,
                Some(&tok),
                Some("access_token=not-a-valid-jwt"),
                body,
            )
            .await?;
            assert_eq!(st, 200, "invalid cookie must fall through to valid Negotiate on {method} {uri}");
        }

        // 5. Malformed/bad SPNEGO -> 401 + spnego_validation_failed audit + record_ip_failure
        threat.ip_failures.lock().unwrap().clear();
        let (st, www, _) =
            send_req(srv.addr, "OPTIONS", "/caldav/", Some("Negotiate !!!"), None, b"").await?;
        assert_eq!(st, 401);
        assert_eq!(www.as_deref(), Some("Negotiate, Bearer realm=\"mailserver\""));
        assert_eq!(threat.ip_failures.lock().unwrap().len(), 1);
        let bad_events: i64 = owner
            .query_one(
                "SELECT COUNT(*) FROM auth_event_log \
                 WHERE provider='kerberos' AND event='login_failed' \
                   AND details->>'reason'='spnego_validation_failed'",
                &[],
            )
            .await?
            .get(0);
        assert!(bad_events >= 1);

        // 6. Unknown principal & disabled user -> 401 + user_not_found audit
        let tok_unknown = minter.negotiate_header("nobody-here", realm);
        let (st, _, _) =
            send_req(srv.addr, "OPTIONS", "/caldav/", Some(&tok_unknown), None, b"").await?;
        assert_eq!(st, 401);
        let tok_disabled =
            minter.negotiate_header(&format!("neg-disabled-{}", disabled_user.user), realm);
        let (st, _, _) =
            send_req(srv.addr, "OPTIONS", "/carddav/", Some(&tok_disabled), None, b"").await?;
        assert_eq!(st, 401);
        let nf_events: i64 = owner
            .query_one(
                "SELECT COUNT(*) FROM auth_event_log \
                 WHERE provider='kerberos' AND event='login_failed' \
                   AND details->>'reason'='user_not_found'",
                &[],
            )
            .await?
            .get(0);
        assert!(nf_events >= 2);

        // 7. TOTP user refused (401 + Go-parity login event, no failure record)
        threat.records.lock().unwrap().clear();
        let tok_totp = minter.negotiate_header(&format!("neg-totp-{}", totp_user.user), realm);
        let (st, www, _) =
            send_req(srv.addr, "OPTIONS", "/caldav/", Some(&tok_totp), None, b"").await?;
        assert_eq!(st, 401);
        assert_eq!(www.as_deref(), Some("Negotiate, Bearer realm=\"mailserver\""));
        assert!(
            threat.records.lock().unwrap().is_empty(),
            "TOTP policy refusal must not strike ThreatGate"
        );
        let totp_login: i64 = owner
            .query_one(
                "SELECT COUNT(*) FROM auth_event_log \
                 WHERE user_id=$1 AND provider='kerberos' AND event='login'",
                &[&totp_user.user],
            )
            .await?
            .get(0);
        assert_eq!(totp_login, 1);

        // 8. Guest user with krb5_principal refused BEFORE RuntimeGate (401 + guest_refused, NO login row)
        set_runtime_flags(&owner, &["feature.device_trust_enforcement"]).await?;
        let tok_guest = minter.negotiate_header(&format!("neg-guest-{}", guest_user.user), realm);
        let (st, _, _) = send_req(
            srv.addr,
            "POST",
            "/api/drive/native-token",
            Some(&tok_guest),
            None,
            b"{}",
        )
        .await?;
        assert_eq!(st, 401, "guest must be refused 401 before device-trust 403");
        let guest_logins: i64 = owner
            .query_one(
                "SELECT COUNT(*) FROM auth_event_log WHERE user_id=$1 AND event='login'",
                &[&guest_user.user],
            )
            .await?
            .get(0);
        assert_eq!(guest_logins, 0, "guest must never get event='login'");
        let guest_refused: i64 = owner
            .query_one(
                "SELECT COUNT(*) FROM auth_event_log \
                 WHERE user_id=$1 AND provider='kerberos' AND event='login_failed' \
                   AND details->>'reason'='guest_refused'",
                &[&guest_user.user],
            )
            .await?
            .get(0);
        assert_eq!(guest_refused, 1);

        // 9. Account lockout check prevents event='login' write
        set_runtime_flags(&owner, &[]).await?;
        *threat.account_lockout.lock().unwrap() = (ThreatAction::Reject, Duration::ZERO);
        let before_member_logins: i64 = owner
            .query_one(
                "SELECT COUNT(*) FROM auth_event_log WHERE user_id=$1 AND event='login'",
                &[&member.user],
            )
            .await?
            .get(0);
        let tok_locked = minter.negotiate_header(&format!("neg-member-{}", member.user), realm);
        let (st, _, _) =
            send_req(srv.addr, "OPTIONS", "/caldav/", Some(&tok_locked), None, b"").await?;
        assert_eq!(st, 401);
        let after_member_logins: i64 = owner
            .query_one(
                "SELECT COUNT(*) FROM auth_event_log WHERE user_id=$1 AND event='login'",
                &[&member.user],
            )
            .await?
            .get(0);
        assert_eq!(
            after_member_logins, before_member_logins,
            "locked-out user must not write auth_event_log login row"
        );
        *threat.account_lockout.lock().unwrap() = (ThreatAction::Allow, Duration::ZERO);

        // 10. RuntimeGate via Arc<RuntimeAccess>:
        //     (a) device_trust_enforcement -> 403 device_compliance_unverifiable
        set_runtime_flags(&owner, &["feature.device_trust_enforcement"]).await?;
        let tok_dt = minter.negotiate_header(&format!("neg-member-{}", member.user), realm);
        let (st, _, bytes) =
            send_req(srv.addr, "OPTIONS", "/caldav/", Some(&tok_dt), None, b"").await?;
        assert_eq!(st, 403);
        let v: Value = serde_json::from_slice(&bytes)?;
        assert_eq!(v["title"], "device_compliance_unverifiable");

        //     (b) CA policy targeting auth_method="basic_auth" allows Kerberos;
        //         CA policy targeting auth_method="kerberos" blocks Kerberos (403)
        set_runtime_flags(
            &owner,
            &["feature.cae_runtime", "feature.conditional_access"],
        )
        .await?;
        owner
            .execute(
                "INSERT INTO conditional_access_policies(name,priority,enabled,state,scope_type,scope_target,conditions,actions) \
                 VALUES('dav-neg-basic-only', 1, TRUE, 'on', 'user', $1, \
                        '{\"auth_method\":\"basic_auth\"}'::jsonb, \
                        '{\"grants\":[{\"type\":\"block\"}],\"reason\":\"ca block\"}'::jsonb)",
                &[&member.user.to_string()],
            )
            .await?;
        // Fresh server so RuntimeAccess engine loads the policy
        srv.close().await;
        let srv_ca = spawn_dav_gateway(
            &db,
            &exec,
            keys.clone(),
            Some(chain.clone()),
            threat.clone(),
            Some(verifier.clone()),
            drive_secret,
            Some(go_upstream),
        )
        .await?;
        let tok_ca1 = minter.negotiate_header(&format!("neg-member-{}", member.user), realm);
        let (st, _, _) =
            send_req(srv_ca.addr, "OPTIONS", "/caldav/", Some(&tok_ca1), None, b"").await?;
        assert_eq!(st, 200, "basic_auth-only CA policy must not block Kerberos");
        srv_ca.close().await;

        owner
            .execute(
                "UPDATE conditional_access_policies SET conditions='{\"auth_method\":\"kerberos\"}'::jsonb \
                 WHERE name='dav-neg-basic-only'",
                &[],
            )
            .await?;
        let srv_ca2 = spawn_dav_gateway(
            &db,
            &exec,
            keys.clone(),
            Some(chain.clone()),
            threat.clone(),
            Some(verifier.clone()),
            drive_secret,
            Some(go_upstream),
        )
        .await?;
        let tok_ca2 = minter.negotiate_header(&format!("neg-member-{}", member.user), realm);
        let (st, _, _) =
            send_req(srv_ca2.addr, "OPTIONS", "/caldav/", Some(&tok_ca2), None, b"").await?;
        assert_eq!(st, 403, "kerberos CA policy must block Kerberos via Proof::kerberos");
        srv_ca2.close().await;

        owner
            .execute(
                "DELETE FROM conditional_access_policies WHERE name='dav-neg-basic-only'",
                &[],
            )
            .await?;

        //     (b2) device_lockdown enforces enrollment (BZ095) including POST /api/drive/native-token
        let prev_bg: Option<String> = owner
            .query_opt(
                "SELECT value::text FROM system_config WHERE key='ca_break_glass_user_ids'",
                &[],
            )
            .await?
            .map(|r| r.get(0));
        owner
            .execute(
                "INSERT INTO system_config(key, value) VALUES('ca_break_glass_user_ids', '[999999999]'::jsonb) \
                 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                &[],
            )
            .await?;
        set_runtime_flags(
            &owner,
            &[
                "feature.cae_runtime",
                "feature.conditional_access",
                "feature.device_lockdown",
            ],
        )
        .await?;
        let srv_ld = spawn_dav_gateway(
            &db,
            &exec,
            keys.clone(),
            Some(chain.clone()),
            threat.clone(),
            Some(verifier.clone()),
            drive_secret,
            Some(go_upstream),
        )
        .await?;
        let tok_ld = minter.negotiate_header(&format!("neg-member-{}", member.user), realm);
        let (st, _, bytes) = send_req(
            srv_ld.addr,
            "POST",
            "/api/drive/native-token",
            Some(&tok_ld),
            None,
            b"{}",
        )
        .await?;
        assert_eq!(st, 403, "device_lockdown must refuse unenrolled Kerberos POST");
        let v: Value = serde_json::from_slice(&bytes)?;
        assert_eq!(v["code"], "BZ095");
        srv_ld.close().await;
        if let Some(prev) = prev_bg {
            owner
                .execute(
                    "UPDATE system_config SET value = $1::text::jsonb WHERE key='ca_break_glass_user_ids'",
                    &[&prev],
                )
                .await?;
        } else {
            owner
                .execute("DELETE FROM system_config WHERE key='ca_break_glass_user_ids'", &[])
                .await?;
        }

        //     (c) CAE scope='all' revocation -> 401 session_revoked
        set_runtime_flags(&owner, &["feature.cae_runtime"]).await?;
        owner
            .execute(
                "INSERT INTO session_revocations(user_id, scope, not_before, expires_at, reason) \
                 VALUES($1, 'all', now() + interval '1 minute', now() + interval '1 hour', 'test')",
                &[&member.user],
            )
            .await?;
        let srv_cae = spawn_dav_gateway(
            &db,
            &exec,
            keys.clone(),
            Some(chain.clone()),
            threat.clone(),
            Some(verifier.clone()),
            drive_secret,
            Some(go_upstream),
        )
        .await?;
        let tok_cae = minter.negotiate_header(&format!("neg-member-{}", member.user), realm);
        let (st, _, bytes) =
            send_req(srv_cae.addr, "OPTIONS", "/caldav/", Some(&tok_cae), None, b"").await?;
        assert_eq!(st, 401);
        let v: Value = serde_json::from_slice(&bytes)?;
        assert_eq!(v["detail"], "Session has been revoked. Sign in again.");
        srv_cae.close().await;
        owner
            .execute("DELETE FROM session_revocations WHERE user_id=$1", &[&member.user])
            .await?;

        // 11. Real setjoin_threat::Gate: 1x rate_limit_counters burn + ip: lockout escalation
        set_runtime_flags(&owner, &[]).await?;
        owner
            .execute("DELETE FROM rate_limit_counters WHERE key='auth:http:127.0.0.1'", &[])
            .await?;
        owner
            .execute(
                "DELETE FROM auth_lockouts WHERE lockout_key IN ('ip:127.0.0.1', $1, $2)",
                &[
                    &format!("user:{}", member_email.to_lowercase()),
                    &format!("ip_user:127.0.0.1:{}", member_email.to_lowercase()),
                ],
            )
            .await?;
        let mut overrides = HashMap::new();
        overrides.insert("feature.rate_limit".into(), true);
        overrides.insert("feature.threat_feed".into(), false);
        overrides.insert("feature.geo_block".into(), false);
        overrides.insert("feature.spray_detect".into(), false);
        overrides.insert("feature.captcha".into(), false);
        overrides.insert("feature.tarpit".into(), false);
        overrides.insert("feature.conditional_access".into(), false);
        let real_gate = ThreatGateImpl::load(
            exec.clone(),
            WorkerPools::from_dsn(&db.dsn)?,
            ThreatConfig {
                overrides,
                rate_limit_per_min: 100,
                ..Default::default()
            },
            None,
        )
        .await?;
        let srv_real = spawn_dav_gateway(
            &db,
            &exec,
            keys.clone(),
            Some(chain.clone()),
            real_gate,
            Some(verifier.clone()),
            drive_secret,
            Some(go_upstream),
        )
        .await?;
        let tok_rl = minter.negotiate_header(&format!("neg-member-{}", member.user), realm);
        let (st, _, _) =
            send_req(srv_real.addr, "OPTIONS", "/caldav/", Some(&tok_rl), None, b"").await?;
        assert_eq!(st, 200);
        let rl_count: i32 = owner
            .query_one(
                "SELECT count FROM rate_limit_counters WHERE key='auth:http:127.0.0.1'",
                &[],
            )
            .await?
            .get(0);
        assert_eq!(rl_count, 1, "valid Kerberos must burn rate_limit_counters once, not twice");

        // Invalid SPNEGO escalates ip:127.0.0.1 lockout row
        let (st, _, _) = send_req(
            srv_real.addr,
            "OPTIONS",
            "/caldav/",
            Some("Negotiate !!!"),
            None,
            b"",
        )
        .await?;
        assert_eq!(st, 401);
        let ip_fails: i32 = owner
            .query_one(
                "SELECT failed_count FROM auth_lockouts WHERE lockout_key='ip:127.0.0.1'",
                &[],
            )
            .await?
            .get(0);
        assert!(ip_fails >= 1, "bad SPNEGO must escalate ip: lockout");

        // Armed user: lockout blocks Kerberos via check_account_lockout
        owner
            .execute(
                "SELECT lockout_arm($1, 10)",
                &[&format!("user:{}", member_email.to_lowercase())],
            )
            .await?;
        let tok_user_lock = minter.negotiate_header(&format!("neg-member-{}", member.user), realm);
        let (st, _, _) =
            send_req(srv_real.addr, "OPTIONS", "/caldav/", Some(&tok_user_lock), None, b"").await?;
        assert_eq!(st, 401, "armed user lockout must reject Kerberos");
        srv_real.close().await;

        assert_eq!(go_hits.load(Ordering::SeqCst), 0);
        Ok::<_, BoxError>(())
    })
    .catch_unwind()
    .await;

    // Cleanup all mutated DB state
    for key in &toggle_keys {
        if let Some((_, on)) = saved_toggles.iter().find(|(k, _)| k == key) {
            owner
                .execute(
                    "INSERT INTO feature_toggles(key,enabled) VALUES($1,$2) \
                     ON CONFLICT(key) DO UPDATE SET enabled=$2",
                    &[key, on],
                )
                .await?;
        } else {
            owner
                .execute("DELETE FROM feature_toggles WHERE key=$1", &[key])
                .await?;
        }
    }
    owner
        .execute(
            "UPDATE auth_methods SET enabled=$1 WHERE slug='kerberos'",
            &[&saved_krb_enabled],
        )
        .await?;
    owner
        .execute(
            "DELETE FROM conditional_access_policies WHERE name='dav-neg-basic-only'",
            &[],
        )
        .await?;
    owner
        .execute(
            "DELETE FROM session_revocations WHERE user_id = ANY($1)",
            &[&vec![
                member.user,
                cookie_user.user,
                totp_user.user,
                guest_user.user,
            ]],
        )
        .await?;
    owner
        .execute(
            "DELETE FROM rate_limit_counters WHERE key='auth:http:127.0.0.1'",
            &[],
        )
        .await?;
    owner
        .execute(
            "DELETE FROM auth_lockouts WHERE lockout_key IN ('ip:127.0.0.1', $1, $2)",
            &[
                &format!("user:{}", member_email.to_lowercase()),
                &format!("ip_user:127.0.0.1:{}", member_email.to_lowercase()),
            ],
        )
        .await?;
    owner
        .execute(
            "DELETE FROM auth_event_log WHERE provider='kerberos' AND (user_id = ANY($1) OR user_id IS NULL)",
            &[&vec![member.user, cookie_user.user, totp_user.user, guest_user.user, disabled_user.user]],
        )
        .await?;
    let _ = owner
        .execute(
            "DELETE FROM guest_accounts WHERE user_id=$1",
            &[&guest_user.user],
        )
        .await;
    let _ = guest_email;
    fixture::remove(&owner, &disabled_user).await?;
    fixture::remove(&owner, &guest_user).await?;
    fixture::remove(&owner, &totp_user).await?;
    fixture::remove(&owner, &cookie_user).await?;
    fixture::remove(&owner, &member).await?;

    match res {
        Ok(inner) => inner,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}
